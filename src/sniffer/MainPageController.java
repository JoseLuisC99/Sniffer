/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 *
 * @author cuent
 */
public class MainPageController implements Initializable {
    @FXML private RadioButton listen_frames;
    @FXML private RadioButton load_file;
    @FXML private Spinner<Integer> number_frames;
    @FXML private ComboBox<String> filter;
    @FXML private ComboBox<String> interface_network;
    @FXML private Hyperlink filename;
    @FXML private Button choose_file;
    @FXML private Button start;
    private ToggleGroup options;
    private File file;

    private List<PcapIf> alldevs;
    private boolean listen = true;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        SpinnerValueFactory<Integer> n_frames = new SpinnerValueFactory.IntegerSpinnerValueFactory(5, 30, 10);
        number_frames.setValueFactory(n_frames);

        ObservableList<String> filters = FXCollections.observableArrayList("", "ip", "arp or rarp", "icmp");
        filter.setItems(filters);
        filter.setValue("");

        options = new ToggleGroup();
        listen_frames.setToggleGroup(options);
        load_file.setToggleGroup(options);

        choose_file.setDisable(true);
        filename.setDisable(true);

        getDevices();
        ObservableList<String> interfaces_names = FXCollections.observableArrayList();
        if(alldevs.isEmpty()){
            listen_frames.setDisable(true);
            number_frames.setDisable(true);
            filter.setDisable(true);
            interface_network.setDisable(true);
            choose_file.setDisable(false);
            filename.setDisable(false);
            listen_frames.setSelected(false);
            load_file.setSelected(true);
            listen = false;
        }
        else{
            for(PcapIf device : alldevs){
                String descrip = device.getDescription() + ": " + device.getName();
                interfaces_names.add(descrip);
            }
        }
        interface_network.setItems(interfaces_names);

        listen_frames.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                number_frames.setDisable(false);
                filter.setDisable(false);
                interface_network.setDisable(false);
                choose_file.setDisable(true);
                filename.setDisable(true);
                listen = !listen;
            }
        });
        load_file.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                number_frames.setDisable(true);
                filter.setDisable(true);
                interface_network.setDisable(true);
                choose_file.setDisable(false);
                filename.setDisable(false);
                listen = !listen;
            }
        });
        choose_file.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                FileChooser fileChooser = new FileChooser();
                FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("PCAP files (*.pcap)", "*.pcap");
                fileChooser.getExtensionFilters().add(extFilter);
                file = fileChooser.showOpenDialog(choose_file.getScene().getWindow());
                if(file != null){
                    filename.setText(file.getAbsolutePath());
                }
            }
        });
        start.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if(listen){
                    if(interface_network.getSelectionModel().getSelectedIndex() >= 0){
                        PcapIf device = alldevs.get(interface_network.getSelectionModel().getSelectedIndex());
                        int snaplen = 64 * 1024, flags = Pcap.MODE_PROMISCUOUS;
                        Captura cap = new Captura(device, snaplen, flags, -1, number_frames.getValue(), filter.getValue());
                    }
                }
                else{
                    if(!file.getPath().equals("") && file.exists()){
                        Captura cap = new Captura(file, filter.getValue());
                    }
                }
            }
        });
    }

    private void getDevices(){
        alldevs = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();
        if(Pcap.findAllDevs(alldevs, errbuf) == Pcap.NOT_OK || alldevs.isEmpty()){
            System.err.println("No puede leerse la lista de dispositivos.\nError: " + errbuf.toString());
            return;
        }
    }

    private String getDeviceInfo(int i){
        try{
            PcapIf device = alldevs.get(i);
            final byte[] mac = device.getHardwareAddress();
            String dirMac = mac == null ? "No tiene direccion MAC" : asString(mac);
            String info = device.getName() + " [" +  device.getDescription() + "], MAC: [" + dirMac + "]";
            return info;
        }
        catch(IOException ex){
            ex.printStackTrace();
            return "";
        }
    }

    private static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0)
                buf.append(':');
            if (b >= 0 && b < 16)
                buf.append('0');
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }
        return buf.toString();
    }
}
