package Protocols;
import org.jnetpcap.protocol.network.Icmp;

public class ICMP {
    private static final int type = 0, code = 1, checksum = 2;
    private String[] Header = new String[16];
    private String message;

    private Icmp ICMP;

    public ICMP(Icmp ICMP) throws Exception {
        this.ICMP = ICMP;
        createHeader();
    }
    private void createHeader() throws Exception {
        //Type
        Header[type] = String.valueOf(ICMP.type());
        //Code
        Header[code]=String.valueOf(ICMP.code());
        //Checksum
        int cs=ICMP.checksum();
        Header[checksum] = String.valueOf(Integer.toHexString(cs));        
        //Impresiones
        if(Header[type].equals("0") && Header[code].equals("0"))
        {
                message = "Echo reply";
        }
        else if (Header[type].equals("3"))
        {
            switch(Integer.parseInt(Header[code]))
            {
                case 0:
                    message = "Network unreachable";
                    break;
                case 1:
                    message = "Host unreachable";
                    break;
                case 2:
                    message = "Protocol unreachable";
                    break;
                case 3:
                    message = "Port unreachable";
                    break;
                case 4:
                    message = "Fragmentation required, but do not fragment bit set";
                    break;
                case 5:
                    message = "Source route failed";
                    break;
                case 6:
                    message = "Destination network unknown";
                    break;
                case 7:
                    message = "Destination host unknown";
                    break;
                case 8:
                    message = "Source host isolated error (military use only)";
                    break;
                case 9:
                    message = "The destionation network is administratively prohibited";
                    break;
                case 10:
                    message = "The destination host is administartively prohibited";
                    break;
                case 11:
                    message = "The network is unreachable for Type Of Service";
                    break;
                case 12:
                    message = "The host is unreachable for Type Of Service";
                    break;
                case 13:
                    message = "Communication administratively prohibited (administrative filtering prevents packet from being forwarded)";
                    break;
                case 14:
                    message = "Host precedence violation (indicates the requested precedence is not permitted for the combination of host or network and port)";
                    break;
                case 15:
                    message = "Precedence cutoff in effect (precedence of datagram is below the level set by the network administrators)";
                    break;
                    
            }//Fin de switch
        }
        else if (Header[type].equals("4") && Header[code].equals("0"))
        {
            message = "Source Quench";
        }
        else if (Header[type].equals("5"))
        {
            message = "Redirect.";
            switch (Integer.parseInt(Header[code]))
            {
                case 0:
                    message = "Network redirect";
                    break;
                case 1:
                    message = "Host redirect";
                    break;
                case 2:
                    message = "Network redirect for this Type Of Service";
                    break;
                case 3:
                    message = "Host redirect for this Type Of Service";
                    break;
            }
        }
        else if(Header[type].equals("8") && Header[code].equals("0"))
        {
            message = "Echo Request";
        }
        else if(Header[type].equals("11"))
        {
            switch(Integer.parseInt(Header[code]))
            {
                case 0: 
                    message = "transit TTL exceeded";
                    break;
                case 1:
                    message = "reasembly TTL exceeded";
            }
        }
        else if(Header[type].equals("12"))
        {
            switch(Integer.parseInt(Header[code]))
            {
                case 0: 
                    message = "Pointer problem";
                    break;
                case 1:
                    message = "Missing a required operand";
                    break;
                case 2:
                    message = "Bad length";
                    break;
            }
        }
        else if (Header[type].equals("13") && Header[code].equals("0"))
        {
            message = "Timestamp Request";
        }
        else if (Header[type].equals("14") && Header[code].equals("0"))
        {
            message = "Timestamp Reply";
        }
        
    }

    public String getType(){
        return Header[type];
    }
    public String getCode(){
        return Header[code];
    }
    public String getChecksum(){
        return Header[checksum];
    }
    public String getMessage(){
        return message;
    }

}