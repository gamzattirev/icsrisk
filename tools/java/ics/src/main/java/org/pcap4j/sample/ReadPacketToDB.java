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
import java.sql.*;
import org.pcap4j.sample.ProtocolResolver;
import org.pcap4j.sample.Const;

@SuppressWarnings("javadoc")
public class ReadPacketToDB {

	private static final int COUNT = 100;

	private static final String PCAP_FILE_KEY = ReadPacketToDB.class.getName() + ".pcapFile";
	private static final String PCAP_FILE_DIR = System.getProperty(PCAP_FILE_KEY, "src/main/resources/");
	private static final String sql0 = "truncate table packet";
	private static final String sql = "INSERT INTO packet(srcip,dstip,srcport,dstport,protocol,service) values(?, ?, ?, ?, ?, ?)";

	private ReadPacketToDB() {
		
	}
	

	public static void main(String[] args) throws PcapNativeException, NotOpenException {
		PcapHandle handle;
		Connection con = null;
		PreparedStatement ps = null;
		Statement stmt = null;
		
		String truncate=args[0];
		
		try {
			Class.forName("com.mysql.jdbc.Driver");
			con = DriverManager.getConnection("jdbc:mysql://localhost/ics", "root", Const.DBPASS);
			ps = con.prepareStatement(sql);
			con.setAutoCommit(false);
			if(null!=truncate && truncate.equals("truncate")) {
				stmt = con.createStatement();
				stmt.executeUpdate(sql0);
			}
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		File dir = new File(PCAP_FILE_DIR);
		File[] files = dir.listFiles();
		for (File file : files) {
			String filename = file.getName();
			if (filename.endsWith(".pcapng") || filename.endsWith(".pcap")) {

				try {
					handle = Pcaps.openOffline(PCAP_FILE_DIR+filename, TimestampPrecision.NANO);
				} catch (PcapNativeException e) {
					handle = Pcaps.openOffline(PCAP_FILE_DIR+filename);
				}

				
				

				ProtocolResolver.readCSV();

				for (int i = 0; i < COUNT; i++) {
					try {
						Packet packet = handle.getNextPacketEx();
						Packet payload = packet.getPayload();
						IpV4Header ipv4Header = null;
						TcpHeader tcpHeader=null;
						try {
							ipv4Header = (IpV4Header) payload.getHeader();
						} catch (Exception e) {
							ipv4Header = (IpV4Header)payload.getPayload().getHeader();
						}
						try {
							tcpHeader = (TcpHeader) payload.getPayload().getHeader();
						} catch (Exception e) {
							System.out.println(e);
						}
						if (null == ipv4Header) {
							continue;
						}
						Inet4Address srcAddr = ipv4Header.getSrcAddr();
						Inet4Address dstAddr = ipv4Header.getDstAddr();
						IpNumber protocol = ipv4Header.getProtocol();
						TcpPort dstPort =null;
						TcpPort srcPort =null;
						if(tcpHeader!=null) {
						 dstPort = tcpHeader.getDstPort();
						 srcPort = tcpHeader.getSrcPort();
						}

						String srcip = srcAddr.toString().replace("/", "").trim();
						String dstip = dstAddr.toString().replace("/", "").trim();

						String srcport ="";
						String dstport = "";
						if(srcPort!=null) {
						 srcport = srcPort.toString().split("\\(")[0].trim();
						}
						if(dstPort!=null) {
						 dstport = dstPort.toString().split("\\(")[0].trim();
						}

						String service = ProtocolResolver.portMap.get(dstport);

						System.out.println(srcip + "," + dstip + "," + srcport + "," + dstport + ","
								+ protocol.toString() + "," + service);

						try {
							
							ps.setString(1, srcip);
							ps.setString(2, dstip);
							ps.setString(3, srcport);
							ps.setString(4, dstport);
							ps.setString(5, protocol.toString());
							ps.setString(6, service);
							ps.executeUpdate();
							con.commit();
						} catch (SQLException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} catch (TimeoutException e) {
					} catch (EOFException e) {
						System.out.println("EOF");
						break;
					}
				}

				handle.close();

			}
		}
		try {
			if (stmt != null) {
				stmt.close();
			}
			if (ps != null) {
				ps.close();
			}
			if (con != null) {
				con.close();
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
}
