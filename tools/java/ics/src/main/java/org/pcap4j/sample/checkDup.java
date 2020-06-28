package org.pcap4j.sample;

import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import org.pcap4j.sample.Const;


public class checkDup {
	
	private static final String sql = "select srcip from nwview";
	private static final String sql2 = "select dstip from nwview where srcip=?";
	private static final String sql3 = "select dstip from nwview";
	private static final String sql4 = "select srcip from nwview where dstip=?";
	
	
	public static void main(String[] args) {
		
		Connection con = null;
		PreparedStatement ps = null;
		PreparedStatement ps2 = null;
		PreparedStatement ps3 = null;
		PreparedStatement ps4 = null;
		HashMap<String,List> ipMap=new HashMap<String,List>();
		HashMap<String,List> ipMap2=new HashMap<String,List>();
		
		try {
			Class.forName("com.mysql.jdbc.Driver");
			con = DriverManager.getConnection("jdbc:mysql://localhost/ics", "root", Const.DBPASS);
			ps = con.prepareStatement(sql);
			ps2 = con.prepareStatement(sql2);
			ps3 = con.prepareStatement(sql3);
			ps4 = con.prepareStatement(sql4);
			
			ResultSet rs = ps.executeQuery();
			while (rs.next()) {
				String ip = rs.getString("srcip");
				ps2.setString(1, ip);
				ResultSet rs2 = ps2.executeQuery();
				List<String> ipList=new ArrayList<String>();
				while (rs2.next()) {
					String ip2=rs2.getString("dstip");
					ipList.add(ip2);
				}
				ipMap.put(ip,ipList);
			}
			
			ResultSet rs3 = ps3.executeQuery();
			while (rs3.next()) {
				String ip = rs3.getString("dstip");
				ps4.setString(1, ip);
				ResultSet rs2 = ps4.executeQuery();
				List<String> ipList=new ArrayList<String>();
				while (rs2.next()) {
					String ip2=rs2.getString("srcip");
					ipList.add(ip2);
				}
				ipMap2.put(ip,ipList);
			}
			
			for (Iterator it = ipMap.entrySet().iterator(); it.hasNext();) {
				Map.Entry<String, List<String>> entry = (Map.Entry<String, List<String>>) it.next();
				String srcip = entry.getKey();
				List<String> list=entry.getValue();
				for(String dstip:list) {
					List<String> srcList=ipMap.get(dstip);
					if(null!=srcList &&srcList.contains(srcip)) {
						System.out.println(srcip+","+dstip);
					}
				}
			}
		
			
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} finally {
			try {
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

}
