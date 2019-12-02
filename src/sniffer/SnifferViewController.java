package sniffer;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.PieChart;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;

public class SnifferViewController implements Initializable{
    @FXML private TextArea captura;
    @FXML private Button guardar;
    @FXML private PieChart grafica;
    @FXML private ProgressBar progreso;
    private ObservableList<PieChart.Data> data;
    private Captura cap;
    int max_packets;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        data = FXCollections.observableArrayList(
                new PieChart.Data("IPv4", 0),
                new PieChart.Data("ARP", 0),
                new PieChart.Data("IEEE", 0),
                new PieChart.Data("ICMP", 0)
        );
        grafica.setLabelsVisible(true);
        grafica.setData(data);
        guardar.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                FileChooser fileChooser = new FileChooser();
                FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("PCAP files (*.pcap)", "*.pcap");
                fileChooser.getExtensionFilters().add(extFilter);
                File file = fileChooser.showSaveDialog(guardar.getScene().getWindow());
                if(file != null){
                    cap.dump(file.getAbsolutePath());
                }
            }
        });
    }

    public void init(Captura cap, int maxValue){
        this.cap = cap;
        this.max_packets = maxValue;
    }

    synchronized public void addText(String text){
        Platform.runLater(new Runnable() {
            @Override
            public void run() {
                captura.appendText(text);
            }
        });
    }

    synchronized public void updateChart(int ipv4, int arp, int ieee, int icmp){
        Platform.runLater(new Runnable() {
            @Override
            public void run() {
                int actualProgess = ipv4 + arp + ieee + icmp;
                data.set(0, new PieChart.Data("IPv4", ipv4));
                data.set(1, new PieChart.Data("ARP", arp));
                data.set(2, new PieChart.Data("IEEE", ieee));
                data.set(3, new PieChart.Data("ICMP", icmp));
            }
        });
    }
    synchronized public void updateProgress(int ipv4, int arp, int ieee, int icmp){
        Platform.runLater(new Runnable() {
            @Override
            public void run() {
                int actualProgess = ipv4 + arp + ieee + icmp;
                progreso.setProgress((float)max_packets/(float)actualProgess);
            }
        });
    }
}
