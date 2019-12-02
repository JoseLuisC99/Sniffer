package sniffer;

import Protocols.ARP;
import Protocols.IEEE;
import Protocols.IP;
import Protocols.ICMP;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;

public class Captura implements Runnable{
    SnifferViewController controller;

    Pcap pcap;
    PcapPacketHandler<String> jpacketHandler;
    String[] sType, uType = new String[32];
    StringBuilder errbuf;
    int numPackets, timeout;
    public List<PacketPair> packets;
    public Thread t;
    int counterIP, counterARP, counterICMP, counterIEEE;
    
    public Captura(File file, String filtro){
        this();
        numPackets = -1;
        timeout = -1;
        controller.init(this, 0);
        
        pcap = Pcap.openOffline(file.getPath(), errbuf);
        if (pcap == null) {
            System.err.printf("Error al abrir el archivo " + file.getPath() + ": " + errbuf.toString());
        }
        else{
            crearFiltro(filtro);
            t = new Thread(this);
            t.start();
        }
    }
    
    public Captura(PcapIf device, int snaplen, int flags, int timeout, int numPackets, String filtro){
        this();
        this.numPackets = numPackets;
        this.timeout = timeout;
        controller.init(this, numPackets);
        
        pcap = Pcap.openLive(device.getName(), snaplen, flags, 10000, errbuf);
        if (pcap == null) {
            System.err.printf("Error al abrir el dispositivo " + device.getName() + ": " + errbuf.toString());
        }
        else{
            crearFiltro(filtro);
            t = new Thread(this);
            t.start();
        }
    }
    
    private Captura(){
        counterIP = 0;
        counterARP = 0;
        counterICMP = 0;
        counterIEEE = 0;

        FXMLLoader loader = new FXMLLoader(getClass().getResource("../sniffer/SnifferView.fxml"));
        Stage stage = new Stage();
        try {
            stage.setScene(new Scene((Pane) loader.load()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        controller = loader.<SnifferViewController>getController();
        stage.show();


        
        this.packets = new ArrayList<>();
        errbuf = new StringBuilder();
        
        sType = new String[]{
            "Receive Ready (RR)",
            "Receive Not Ready (RNR)",
            "Reject (REJ)",
            "Selective Reject (SREJ)"
        };
        uType = new String[]{
            "Unnumbered Information (UI)",
            "Set Initialization Mode (SIM)",
            "Nonreserved 0 (NR0)",
            "Set Asynchronous Response (SARM)",
            "Unnumbered Poll (UP)",
            "Request Initialization Mode (RIM)",
            "Disconnect Mode (DM)",
            "Set Asynchronous Balanced Mode(SABM)",
            "Disconnect (DISC)",
            "Request Disconnect (RD)",
            "Nonreserved 2 (NR2)",
            "Set Asynchronous Response Extended Mode (SARME)",
            "Unnumbered Aknowledgement (UA)",
            "Invalido",
            "Invalido",
            "Set Asynchronous Balanced Extended Mode (SABME)",
            "Set Normal Response (SNRM)",
            "Frame Reject (FRMR)",
            "Nonreserved 1 (NR1)",
            "Reset (RSET)",
            "Invalido",
            "Invalido",
            "Invalido",
            "Exchange Identification (XID)",
            "Invalido",
            "Configure For Test (CFGR)",
            "Nonreserved 3 (NR3)",
            "Set Normal Response Extended Mode (SNRME)",
            "Test (TEST)",
            "Invalido",
            "Invalido",
            "Beacon (BCN)"
        };
        
        jpacketHandler = (PcapPacket packet, String user) -> {
            packets.add(new PacketPair(packet, user));
            analizar(packet, user);
        };
    }
    
    private void crearFiltro(String filtro){
        PcapBpfProgram filter = new PcapBpfProgram();
        int optimize = 0;
        int netmask = 0;
        int r2 = pcap.compile(filter, filtro, optimize, netmask);
        if (r2 != Pcap.OK) {
            System.err.printf("Error en el filtro: " + pcap.getErr());
        }
        pcap.setFilter(filter);
    }
    
    private void analizar(PcapPacket packet, String user){
        System.out.println("OK");
        controller.addText("\n");
        for(int i = 0; i < 100; i++)
            controller.addText("*");
        controller.addText(
            String.format(
                "\n\nPaquete recibido el %s caplen=%-4d longitud=%-4d %s\n\n",
                new Date(packet.getCaptureHeader().timestampInMillis()),
                packet.getCaptureHeader().caplen(),
                packet.getCaptureHeader().wirelen(),
                user
            )
        );

        for(int i = 0; i < packet.size(); i++){
            controller.addText(String.format("%02X ", packet.getUByte(i)));
            if(i % 16 == 15)
                controller.addText("\n");
        }
        
        selectProtocol(packet);
    }
    
    private void selectProtocol(PcapPacket packet) {
        int type = packet.getUByte(12) * 256 + packet.getUByte(13);
        controller.addText(String.format("\n\tLongitud: %d (0x%04X)", type, type));
        //Is ethernet
        if (type > 1500) {
            switch (type) {
                //IPv4
                case 2048:
                    analizarIp4(packet);
                    break;
                //ARP
                case 2054:
                    analizarArp(packet);
                    break;
            }

        }
        else
            analizarIeee(packet);
        controller.updateProgress(counterIP, counterARP, counterIEEE, counterICMP);
    }
    
    private void analizarIp4(PcapPacket packet){
        Ip4 ip4 = packet.getHeader(new Ip4());
        if (packet.hasHeader(ip4)) {
            counterIP++;
            try{
                IP ip = new IP(ip4);
                if(ip4.type() == 0x01){
                    counterIP--;
                    analizarICMP(packet);
                }
                
                controller.addText("\n\tTRAMA IPV4");
                controller.addText("\n\t\tVersion IPv" + ip4.version());
                controller.addText("\n\t\tIHL: "+ip4.hlen());
                controller.addText("\n\t\tServicios Diferidos:"+ip4.tos());             
                controller.addText("\n\t\tChecksum: " + ip.getChecksum());
                controller.addText("\n\t\tChecksum valido: " + ip.getIsValidChecksum());
                controller.addText("\n\t\tVersion: " + ip.getVersion());                
                controller.addText("\n\t\tLongitud: " + ip.getlength());               
                controller.addText("\n\t\tID: " + ip.getID());
                controller.addText("\n\t\tX: " + ip.getFlagX());
                controller.addText("\n\t\tY: " + ip.getFlagY());
                controller.addText("\n\t\tOffset: " + ip.getOffset());
                controller.addText("\n\t\tTTL: " + ip.getTTL());
                controller.addText("\n\t\tIP Origen: " + ip.getIP_O());
                controller.addText("\n\t\tIP Destino: " + ip.getIP_D());
                controller.addText("\n\t\tProtocolo: " + ip4.type());
                controller.addText("\n");
            }
            catch(Exception ex){
                System.out.println("Error al iniciar la clase IP:\n" + ex.toString());
            }
        }
        else 
            controller.addText("\n\tEl paquete no contiene un encabezado IP\n");
    }

    private void analizarICMP(PcapPacket packet){
        Icmp icmp = packet.getHeader(new Icmp());
        if (packet.hasHeader(icmp)) {
            counterICMP++;
            try{
                ICMP header = new ICMP(icmp);

                controller.addText("\n\tTRAMA ICMP");
                controller.addText("\n\t\tChecksum: " + header.getChecksum());
                controller.addText("\n\t\tTipo: " + header.getType());
                controller.addText("\n\t\tCódigo: " + header.getCode());
                controller.addText("\n\t\tMensaje: " + header.getMessage());
                controller.addText("\n");
            }
            catch(Exception ex){
                System.out.println("Error al iniciar la clase ICMP:\n" + ex.toString());
            }
        }
        else
            controller.addText("\n\tEl paquete no contiene un encabezado ICMP\n");
    }

    private void analizarArp(PcapPacket packet){
        Arp arp = packet.getHeader(new Arp());
        if (packet.hasHeader(arp)) {
            counterARP++;
            try{
                ARP arpI = new ARP(arp);
                
                controller.addText("\n\tTRAMA ARP");
                controller.addText("\n\t\tEncabezado: " + arpI.getHeader());
                controller.addText("\n\t\tTipo de hardware: " + arpI.getHardwareType());
                controller.addText("\n\t\tTipo de protocolo: " + arpI.getProtocolType());
                controller.addText("\n\t\tLongitud de direccion de hardware: " + arpI.getHardAddLength());
                controller.addText("\n\t\tLongitud de direccion de protocolo: " + arpI.getProtAddLength());
                controller.addText("\n\t\tCodigo de opcion: " + arpI.getOpcode());
                controller.addText("\n\t\tDireccion del hardware remitente: " + arpI.getSenderHardAdd());
                controller.addText("\n\t\tDireccion del protocolo remitente: " + arpI.getSenderProtAdd());
                controller.addText("\n\t\tDireccion del hardware destinatario: " + arpI.getTargHardAdd());
                controller.addText("\n\t\tDireccion del protocolo destinatario: " + arpI.getTargProtAdd());
                controller.addText("\n");
            }
            catch(Exception ex){
                System.out.println("Error al iniciar la clase ARP:\n" + ex.toString());
            }
        }
        else 
            controller.addText("\n\tEl paquete no contiene un encabezado ARP\n");
    }
    
    private void analizarIeee(PcapPacket packet){
        counterIEEE++;
        try{
            IEEE ieee = new IEEE(packet);

            controller.addText("\n\tTRAMA IEEE");
            controller.addText("\n\t\tEncabezado: " + ieee.getHeader());
            controller.addText("\n\t\tMAC Origen: " + ieee.getMac_O());
            controller.addText("\n\t\tMAC Destino: " + ieee.getMac_D());
            controller.addText("\n\t\tLongitud: " + ieee.getLength());
            controller.addText("\n\t\tDSAP: " + ieee.getDSAP());
            controller.addText("\n\t\tSSAP: " + ieee.getSSAP());
            controller.addText("\n\t\tControl: " + ieee.getControl());
            controller.addText("\n\t\tTipo: " + ieee.getTipo());
            controller.addText("\n\t\tOrden: " + ieee.getOrden());
            controller.addText("\n\t\tRespuesta: " + ieee.getRespuesta());
            controller.addText("\n\t\tnR: " + ieee.get_nR() + " - " + ieee.get_nR_dec());
            controller.addText("\n\t\tnS: " + ieee.get_nS() + " - " + ieee.get_nS_dec());
            controller.addText("\n");
        }
        catch(Exception ex){
            System.out.println("Error al iniciar la clase IEEE:\n" + ex.toString());
        }
    }
    
    public void dump(String dumpFile){
        Pcap defaultPcap = Pcap.openOffline(".\\src\\sniffer\\default.pcap", errbuf);
        PcapDumper dumper = defaultPcap.dumpOpen(dumpFile);
        packets.stream().forEach((packetPair) -> {
            dumper.dump(packetPair.packet.getCaptureHeader(), packetPair.packet);
        });
        dumper.close();
        defaultPcap.close();
    }
    
    @Override
    public void run(){
        if(timeout != -1){
            timeout *= 1000;
            long startTime = System.currentTimeMillis();
            while(System.currentTimeMillis() - startTime < timeout)
                pcap.loop(1, jpacketHandler, " ");
        }
        else
            pcap.loop(numPackets, jpacketHandler, " ");
        
        controller.updateChart(counterIP, counterARP, counterIEEE, counterICMP);
        
        pcap.close();
    }
}
