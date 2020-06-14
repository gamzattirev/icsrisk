package org.pcap4j.sample;

import java.io.*;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.Packet.Header;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import java.net.Inet4Address;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.namednumber.TcpPort;

@SuppressWarnings("javadoc")
public class ReadPacketICS {

  private static final int COUNT = 100;

  private static final String PCAP_FILE_KEY = ReadPacketICS.class.getName() + ".pcapFile";
  private static final String PCAP_FILE =
      System.getProperty(PCAP_FILE_KEY, "src/main/resources/opc.pcap");

  private ReadPacketICS() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    PcapHandle handle;
    try {
      handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
    } catch (PcapNativeException e) {
      handle = Pcaps.openOffline(PCAP_FILE);
    }
    
	File file = new File("src/main/resources/packet.csv");
	FileWriter filewriter = null;
	BufferedWriter bw = null;
	PrintWriter pw = null;
	try {
		filewriter = new FileWriter(file);
	} catch (IOException e1) {
		// TODO Auto-generated catch block
		e1.printStackTrace();
	}
	bw = new BufferedWriter(filewriter);
	pw = new PrintWriter(bw);
	pw.println("srcip,dstip,srcport,dstport,protocol");


    for (int i = 0; i < COUNT; i++) {
      try {
        Packet packet = handle.getNextPacketEx();
        Packet payload =packet.getPayload();
        IpV4Header ipv4Header=null;
        try {
        	ipv4Header=(IpV4Header)payload.getHeader();
        } catch (Exception e){
        	continue;
        }
        if(null==ipv4Header) {
        	continue;
        }
        Inet4Address srcAddr=ipv4Header.getSrcAddr();
        Inet4Address dstAddr=ipv4Header.getDstAddr();
        IpNumber protocol=ipv4Header.getProtocol();
        
        TcpHeader tcpHeader=(TcpHeader)payload.getPayload().getHeader();
        TcpPort dstPort=tcpHeader.getDstPort();
        TcpPort srcPort=tcpHeader.getSrcPort();
        
        String srcip=srcAddr.toString().replace("/","");
        String dstip=dstAddr.toString().replace("/","");
        
        String srcport=srcPort.toString().split("\\(")[0];
        String dstport=dstPort.toString().split("\\(")[0];
        
        /*
        System.out.println(handle.getTimestamp());
        System.out.println(protocol+",srcip:"+srcip+",dstip:"+dstip);
        System.out.println("srcPort:"+srcport+",dstPort:"+dstport);
        */
        
        pw.println(srcip+","+dstip+","+srcport+","+dstport+","+protocol.toString());
        
      } catch (TimeoutException e) {
      } catch (EOFException e) {
        System.out.println("EOF");
        break;
      }
    }

    handle.close();
	pw.close();
	try {
		bw.close();
	} catch (IOException e) {
		e.printStackTrace();
	}

  }
}
