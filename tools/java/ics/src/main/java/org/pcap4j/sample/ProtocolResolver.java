package org.pcap4j.sample;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;

public class ProtocolResolver {

	protected static HashMap<String, String> portMap = new HashMap<String, String>();

	public static void readCSV() {
		try {
			File f = new File("src/main/resources/service-names-port-numbers.csv");
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			String protocol = "";
			String port = "";

			while ((line = br.readLine()) != null) {
				try {
					String[] data = line.split(",");
					protocol = data[0];
					port = data[1];
					if(!protocol.isEmpty() && !port.isEmpty()) {
						//System.out.println(protocol + "," + port);
						portMap.put(port,protocol);
					}
				} catch (Exception e) {
					continue;
				}
			}
		} catch (IOException e) {
			System.out.println(e);
		}
	}

	public static void main(String[] args) {
		ProtocolResolver.readCSV();
	}
}
