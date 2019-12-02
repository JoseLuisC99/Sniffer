package Protocols;

import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;

public class IP {

    private static final int version = 0, IHL = 1, TOS = 2, length = 3, id = 4,
            flag0 = 5, flagX = 6, flagY = 7, offset = 9, TTL = 10, protocol = 11,
            checksum = 12, IP_O = 13, IP_D = 14, checksumValid = 15;

    private String[] Header = new String[16];

    private Ip4 IP4;

    public IP(Ip4 IP4) throws Exception {
        this.IP4 = IP4;
        createHeader();
    }

    private void createHeader() throws Exception {
        Header[version] = String.valueOf(IP4.version());
        Header[IHL] = IP4.hlen() + "";
        Header[TOS] = IP4.tos_ECEDescription()+ " " + IP4.tos_ECNDescription();
        Header[length] = String.valueOf(IP4.length());
        Header[id] = String.valueOf(IP4.id());
        Header[flag0] = String.valueOf(0);
        Header[flagX] = String.valueOf(IP4.flags_DF());
        Header[flagY] = String.valueOf(IP4.flags_MF());
        Header[offset] = String.valueOf(IP4.offset());
        Header[TTL] = String.valueOf(IP4.ttl());
        Header[protocol] = String.valueOf(4);
        Header[checksum] = "0x" + Integer.toHexString(IP4.checksum());
        Header[IP_O] = FormatUtils.ip(IP4.source());
        Header[IP_D] = FormatUtils.ip(IP4.destination());
        Header[checksumValid] = "" + IP4.isChecksumValid();
    }

    private String TOStype(String code){
        String str = "", aux = "";
        for(int i = code.length(); i > code.length(); i--){
            if((i >= 0 && i <= 2) && code.charAt(i) == '1')
                str = "prioridad";
            else if(i == 3 && code.charAt(i) == '1')
                str = "retardo";
            else if(i == 4 && code.charAt(i) == '1')
                str = "Desempe�o";
            else if(i == 5 && code.charAt(i) == '1')
                str = "Confiabilidad";
            else aux += code.charAt(i);
        }        
        if(aux.equalsIgnoreCase("00"))
            aux = "Sin capacidad ECN";
        if(aux.equalsIgnoreCase("01"))
            aux = "Con capacidad ECN";
        if(aux.equalsIgnoreCase("10"))
            aux = "Con capacidad ECN";
        if(aux.equalsIgnoreCase("11"))
            aux = "Congestionamiento encontrado";
        return str + " | " + aux;
    }
    
    public String getVersion() {
        return Header[version];
    }

    public String getTOS() {
        return Header[TOS];
    }

    public String getlength() {
        return Header[length];
    }

    public String getID() {
        return Header[id];
    }

    public String getOffset() {
        return Header[offset];
    }

    public String getTTL() {
        return Header[TTL];
    }

    public String getChecksum() {
        return Header[checksum];
    }

    public String getIP_O() {
        return Header[IP_O];
    }

    public String getIP_D() {
        return Header[IP_D];
    }

    public String getIsValidChecksum() {
        return Header[checksumValid];
    }

    public String getFlag0() {
        return Header[flag0];
    }

    public String getFlagX() {
        return Header[flagX];
    }

    public String getFlagY() {
        return Header[flagY];
    }

    public String[] getHeader() {
        return Header;
    }
}

