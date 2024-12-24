package main

import (
    "encoding/binary"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"
    "runtime"
    "strings"
    "sync"
)

type TemplateField struct {
    Type   uint16
    Length uint16
    Name   string
}

type TemplateRecord struct {
    TemplateID uint16
    Fields     []TemplateField
}

var (
    templates      = make(map[uint16]TemplateRecord)
    fieldNameMap   = make(map[uint16]map[uint16]string)
    templatesMutex sync.RWMutex
    configFilePath string
    dataLogPath    string
    debugLogPath   string
    debugEnabled   bool
    wg             sync.WaitGroup
)

// Example field type names map (this should be populated with actual type names)
var templateFieldType = map[uint16]string{
    4:     "PROTOCOL",
    7:     "L4_SRC_PORT",
    8:     "IP_SRC_ADDR",
    10:    "INPUT_SNMP",
    11:    "L4_DST_PORT",
    12:    "IP_DST_ADDR",
    14:    "OUTPUT_SNMP",
    27:    "IPV6_SRC_ADDR",
    28:    "IPV6_DST_ADDR",
    148:   "flowId",
    152:   "flowSTartMilliseconds",
    176:   "ICMP_IPv4_TYPE",
    177:   "ICMP_IPv4_CODE",
    178:   "ICMP_IPv6_TYPE",
    179:   "ICMP_IPv6_CODE",
    225:   "postNATSourceIPv4Address",
    226:   "postNATDestinationIPv4Address",
    227:   "postNAPTSourceTransportPort",
    228:   "postNAPTDestinationTransportPort",
    281:   "postNATSourceIPv6Address",
    282:   "postNATDestinationIPv6Address",
    231:   "initiatorOctets",
    232:   "responderOctets",
    233:   "firewallEvent",
    298:   "initiatorPackets",
    299:   "responderPackets",
    323:   "observationTimeMilliseconds",
    33000: "INGESS_ACL_ID",
    33001: "EGRESS_ACL_ID",
    33002: "FW_EXT_EVENT",
    40000: "AAA_USERNAME",
    // Add other known field types here...
}

func init() {
    flag.StringVar(&configFilePath, "c", "", "Path to the config file (templates.json)")
    flag.StringVar(&dataLogPath, "o", "", "Path to the JSON data output log")
    flag.StringVar(&debugLogPath, "d", "", "Path to the debug log file")
    var cpuCount int
    flag.IntVar(&cpuCount, "cpu", runtime.NumCPU(), "Number of CPUs to use")
    flag.Parse()

    if dataLogPath == "" || configFilePath == "" {
        log.Fatal("Both -o (data log path) and -c (config file path) options are required")
    }

    if debugLogPath != "" {
        debugEnabled = true
    }

    runtime.GOMAXPROCS(cpuCount)
    loadTemplatesFromFile()
}

func loadTemplatesFromFile() {
    data, err := ioutil.ReadFile(configFilePath)
    if err != nil {
        // log.Printf("Error reading templates config file: %v", err)
        logDebug(fmt.Sprintf("Error reading templates config file: %v", err))
        return
    }
    if len(data) == 0 {
        // log.Println("Templates config file is empty")
        logDebug("Templates config file is empty")
        return
    }
    var storedTemplates map[uint16]TemplateRecord
    err = json.Unmarshal(data, &storedTemplates)
    if err != nil {
        // log.Printf("Error unmarshalling templates config file: %v", err)
        logDebug(fmt.Sprintf("Error unmarshalling templates config file: %v", err))
        return
    }
    templatesMutex.Lock()
    for id, template := range storedTemplates {
        templates[id] = template
        if fieldNameMap[id] == nil {
            fieldNameMap[id] = make(map[uint16]string)
        }
        for _, field := range template.Fields {
            fieldNameMap[id][field.Type] = field.Name
        }
    }
    templatesMutex.Unlock()
}

func saveTemplatesToFile() {
    templatesMutex.RLock()
    data, err := json.Marshal(templates)
    templatesMutex.RUnlock()
    if err != nil {
        // log.Println("Error marshalling templates:", err)
        logDebug(fmt.Sprintf("Error marshalling templates: %v", err))
        return
    }
    err = ioutil.WriteFile(configFilePath, data, 0644)
    if err != nil {
        // log.Println("Error writing templates to file:", err)
        logDebug(fmt.Sprintf("Error writing templates to file: %v", err))
    }
}

func handleTemplateRecord(templateID uint16, fields []TemplateField) {
    templatesMutex.Lock()
    templates[templateID] = TemplateRecord{TemplateID: templateID, Fields: fields}
    if fieldNameMap[templateID] == nil {
        fieldNameMap[templateID] = make(map[uint16]string)
    }
    for _, field := range fields {
        fieldName, exists := templateFieldType[field.Type]
        if !exists {
            fieldName = fmt.Sprintf("Field_%d", field.Type)
        }
        field.Name = fieldName
        fieldNameMap[templateID][field.Type] = field.Name
    }
    templatesMutex.Unlock()
    saveTemplatesToFile()
    log.Printf("New template received and stored: TemplateID %d", templateID)
    logDebug(fmt.Sprintf("New template received and stored: TemplateID %d", templateID))
}

func getTemplate(templateID uint16) (TemplateRecord, bool) {
    templatesMutex.RLock()
    template, exists := templates[templateID]
    templatesMutex.RUnlock()
    return template, exists
}

type NFv9Packet struct {
    Version        uint16
    Count          uint16
    SystemUptime   uint32
    UnixSeconds    uint32
    SequenceNumber uint32
    SourceId       uint32
    FlowSets       []interface{}
}

type TemplateFlowSet struct {
    Templates []TemplateRecord
}

type DataFlowSet struct {
    TemplateID uint16
    Records    []DataRecord
}

type DataRecord struct {
    Payload []byte
}

func processPacket(data []byte) {
    version := binary.BigEndian.Uint16(data[0:2])
    if version == 9 {
        packet := parseNetFlowV9Packet(data)
        processNetFlowV9Packet(packet)
    } else if version == 10 {
        packet := parseIPFIXPacket(data)
        processNetFlowV9Packet(packet)
    } else {
        // log.Printf("Unsupported NetFlow/IPFIX version: %d", version)
        logDebug(fmt.Sprintf("Unsupported NetFlow/IPFIX version: %d", version))
    }
}

func processNetFlowV9Packet(packet NFv9Packet) {
    wg.Add(len(packet.FlowSets))
    for _, flowSet := range packet.FlowSets {
        go func(fs interface{}) {
            defer wg.Done()
            switch fs := fs.(type) {
            case TemplateFlowSet:
                for _, template := range fs.Templates {
                    handleTemplateRecord(template.TemplateID, template.Fields)
                }
            case DataFlowSet:
                template, exists := getTemplate(fs.TemplateID)
                if !exists {
                    // log.Printf("Data does not match a known template: TemplateID %d", fs.TemplateID)
                    logDebug(fmt.Sprintf("Data does not match a known template: TemplateID %d", fs.TemplateID))
                    return
                }
                for _, record := range fs.Records {
                    parsedRecord := parseRecordUsingTemplate(record, template)
                    writeRecordToJSON(parsedRecord)
                }
            }
        }(flowSet)
    }
    wg.Wait()
}

func parseRecordUsingTemplate(record DataRecord, template TemplateRecord) map[string]interface{} {
    parsedRecord := make(map[string]interface{})
    offset := 0
    isDNSRequest := false // Flag to detect DNS requests
    isUDP161 := false // Flag to detect UDP 161 which are excessive and uninteresting
    noresponderPackets := false // Flag to detect if there is no response and drop it as uninteresting
    fwExtEvent := false // Flag to detect if this is not a NAT related event and drop it as uninteresting

    for _, field := range template.Fields {
        if offset+int(field.Length) > len(record.Payload) {
            log.Printf("Field length %d exceeds payload length %d for field %s", field.Length, len(record.Payload)-offset, field.Name)
            logDebug(fmt.Sprintf("Field length %d exceeds payload length %d for field %s", field.Length, len(record.Payload)-offset, field.Name))
            break
        }
        value := parseField(record.Payload[offset:], field)
        fieldName := field.Name
        if fieldName == "" {
            fieldName = fmt.Sprintf("Unknown(%d)", field.Type)
        }

        // Check if this record is a DNS request (UDP port 53)
        if fieldName == "L4_DST_PORT" && value == uint16(53) {
            isDNSRequest = true // Mark as DNS request
        }

        // Check if this record is (UDP port 161)
        if fieldName == "L4_DST_PORT" && value == uint16(161) {
            isUDP161 = true // Mark as UDP 161
        }

        // Check if this record contains no responder packets
        if fieldName == "responderPackets" && value == uint64(0) {
            noresponderPackets = true // Mark as no response
        }

        // Check if this record is FW Event 1004
        if fieldName == "FW_EXT_EVENT" && value == uint16(1004) {
            fwExtEvent = true // Mark as no response
        }

        // Check if this record is FW Event 0
        if fieldName == "FW_EXT_EVENT" && value == uint16(0) {
            fwExtEvent = true // Mark as no response
        }

        // Check if this record does not have AAA_USERNAME populated
        if fieldName == "AAA_USERNAME" && value == "" {
            fwExtEvent = true // Mark as no response
        }

        parsedRecord[fieldName] = value
        parsedRecord[fieldName] = value
        offset += int(field.Length)
    }

    if isDNSRequest {
        logDebug("DNS request detected, dropping the request without logging.")
        return nil // Return nil to drop DNS request
    }

    if isUDP161 {
        logDebug("UDP 161 request detected, dropping the request without logging.")
        return nil // Return nil to drop request
    }

    if noresponderPackets {
        logDebug("No response to request detected, dropping without logging.")
        return nil // Return nil to drop request
    }

    if fwExtEvent {
        logDebug("No response to request detected, dropping without logging.")
        return nil // Return nil to drop request
    }

    return parsedRecord
}

func writeRecordToJSON(record map[string]interface{}) {
    if record == nil {
        return // Skip logging for DNS requests or any dropped records
    }

    data, err := json.Marshal(record)
    if err != nil {
        log.Println("Error marshalling record to JSON:", err)
        logDebug(fmt.Sprintf("Error marshalling record to JSON: %v", err))
        return
    }
    if len(data) > 0 {
        writeToFile(dataLogPath, append(data, '\n'))
    }
}

func parseField(payload []byte, field TemplateField) interface{} {
    switch field.Type {
    case 8, 12, 15: // IPv4 addresses
        if field.Length == 4 {
            return net.IP(payload[:field.Length]).String()
        }
    case 225, 226: // postNATSourceIPv4Address and postNATDestinationIPv4Address
        if field.Length == 4 {
            return net.IP(payload[:field.Length]).String()
        }
    case 27, 28: // IPv6 addresses
        if field.Length == 16 {
            return net.IP(payload[:field.Length]).String()
        }
    }

    // General case for other lengths
    switch field.Length {
    case 1:
        return payload[0]
    case 2:
        return binary.BigEndian.Uint16(payload[:field.Length])
    case 4:
        return binary.BigEndian.Uint32(payload[:field.Length])
    case 8:
        return binary.BigEndian.Uint64(payload[:field.Length])
    default:
        if field.Length > 4 { // Assuming it's a string if length > 4 for simplicity
            return strings.TrimRight(string(payload[:field.Length]), "\x00")
        }
        return fmt.Sprintf("Unknown(length: %d)", field.Length)
    }
}

func main() {
    addr := net.UDPAddr{
        Port: 2055,
        IP:   net.ParseIP("0.0.0.0"),
    }
    conn, err := net.ListenUDP("udp", &addr)
    if err != nil {
        log.Fatalf("Failed to set up UDP listener: %v", err)
    }
    defer conn.Close()

    buffer := make([]byte, 4096)
    for {
        n, _, err := conn.ReadFromUDP(buffer)
        if err != nil {
            // log.Printf("Failed to read UDP packet: %v", err)
            logDebug(fmt.Sprintf("Failed to read UDP packet: %v", err))
            continue
        }
        processPacket(buffer[:n])
    }
}

func parseNetFlowV9Packet(data []byte) NFv9Packet {
    var packet NFv9Packet
    packet.Version = binary.BigEndian.Uint16(data[0:2])
    packet.Count = binary.BigEndian.Uint16(data[2:4])
    packet.SystemUptime = binary.BigEndian.Uint32(data[4:8])
    packet.UnixSeconds = binary.BigEndian.Uint32(data[8:12])
    packet.SequenceNumber = binary.BigEndian.Uint32(data[12:16])
    packet.SourceId = binary.BigEndian.Uint32(data[16:20])
    packet.FlowSets = parseFlowSets(data[20:])
    logDebug(fmt.Sprintf("Parsed NetFlow v9 packet: %+v", packet))
    return packet
}

func parseIPFIXPacket(data []byte) NFv9Packet {
    var packet NFv9Packet
    packet.Version = binary.BigEndian.Uint16(data[0:2])
    packet.Count = binary.BigEndian.Uint16(data[2:4])
    packet.SystemUptime = binary.BigEndian.Uint32(data[4:8])
    packet.UnixSeconds = binary.BigEndian.Uint32(data[8:12])
    packet.SequenceNumber = binary.BigEndian.Uint32(data[12:16])
    packet.SourceId = binary.BigEndian.Uint32(data[16:20])
    packet.FlowSets = parseFlowSets(data[20:])
    logDebug(fmt.Sprintf("Parsed IPFIX packet: %+v", packet))
    return packet
}

func parseFlowSets(data []byte) []interface{} {
    var flowSets []interface{}
    offset := 0
    for offset < len(data) {
        flowSetID := binary.BigEndian.Uint16(data[offset : offset+2])
        length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
        if length == 0 {
            break // Prevents infinite loop if length is 0
        }
        if flowSetID == 0 || flowSetID == 2 {
            flowSets = append(flowSets, parseTemplateFlowSet(data[offset:offset+int(length)]))
        } else {
            flowSets = append(flowSets, parseDataFlowSet(data[offset:offset+int(length)]))
        }
        offset += int(length)
    }
    return flowSets
}

func parseTemplateFlowSet(data []byte) TemplateFlowSet {
    var templateFlowSet TemplateFlowSet
    offset := 4
    for offset < len(data) {
        templateID := binary.BigEndian.Uint16(data[offset : offset+2])
        fieldCount := binary.BigEndian.Uint16(data[offset+2 : offset+4])
        var fields []TemplateField
        offset += 4
        for i := 0; i < int(fieldCount); i++ {
            fieldType := binary.BigEndian.Uint16(data[offset : offset+2])
            fieldLength := binary.BigEndian.Uint16(data[offset+2 : offset+4])
            fieldName, exists := templateFieldType[fieldType]
            if !exists {
                fieldName = fmt.Sprintf("Field_%d", fieldType)
            }
            fields = append(fields, TemplateField{Type: fieldType, Length: fieldLength, Name: fieldName})
            offset += 4
        }
        templateFlowSet.Templates = append(templateFlowSet.Templates, TemplateRecord{TemplateID: templateID, Fields: fields})
    }
    return templateFlowSet
}

func parseDataFlowSet(data []byte) DataFlowSet {
    var dataFlowSet DataFlowSet
    dataFlowSet.TemplateID = binary.BigEndian.Uint16(data[0:2])
    dataFlowSet.Records = parseDataRecords(data[4:], dataFlowSet.TemplateID)
    return dataFlowSet
}

func parseDataRecords(data []byte, templateID uint16) []DataRecord {
    var records []DataRecord
    template, exists := getTemplate(templateID)
    if !exists {
        // log.Printf("Data does not match a known template: TemplateID %d", templateID)
        logDebug(fmt.Sprintf("Data does not match a known template: TemplateID %d", templateID))
        return records
    }
    recordLength := 0
    for _, field := range template.Fields {
        recordLength += int(field.Length)
    }
    offset := 0
    for offset < len(data) {
        if offset+recordLength > len(data) {
            if isPadding(data[offset:]) {
                break
            }
            // log.Printf("Data record length mismatch: expected %d, got %d (TemplateID %d, Offset %d, Data %x)", recordLength, len(data)-offset, templateID, offset, data[offset:])
            logDebug(fmt.Sprintf("Data record length mismatch: expected %d, got %d (TemplateID %d, Offset %d, Data %x)", recordLength, len(data)-offset, templateID, offset, data[offset:]))
            break
        }
        records = append(records, DataRecord{Payload: data[offset : offset+recordLength]})
        offset += recordLength
    }
    return records
}

func isPadding(data []byte) bool {
    for _, b := range data {
        if b != 0 {
            return false
        }
    }
    return true
}

func writeToFile(filePath string, data []byte) {
    file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
    if err != nil {
        // log.Println("Error opening file:", err)
        logDebug(fmt.Sprintf("Error opening file: %v", err))
        return
    }
    defer file.Close()

    if len(data) > 0 {
        _, err = file.Write(data)
        if err != nil {
            // log.Println("Error writing to file:", err)
            logDebug(fmt.Sprintf("Error writing to file: %v", err))
        }
    }
}

func logDebug(message string) {
    if debugEnabled {
        file, err := os.OpenFile(debugLogPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
        if err != nil {
            // log.Println("Error opening debug log file:", err)
            return
        }
        defer file.Close()

        _, err = file.WriteString(message + "\n")
        if err != nil {
            // log.Println("Error writing to debug log file:", err)
        }
    }
}

