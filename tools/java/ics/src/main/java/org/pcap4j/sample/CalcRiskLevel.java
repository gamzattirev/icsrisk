package org.pcap4j.sample;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashSet;
import java.sql.*;

public class CalcRiskLevel {

	private static final String sql0 = "truncate table attack_path";
	private static final String sql01 = "truncate table path_risk_level";

	private static final String sql = "select distinct dstip from nwview where srcip=?";

	private static final String sql2 = "select no from attack_path where dstip=?";

	private static final String sql3 = "insert into attack_path(no, srcip, dstip) values(?, ?, ?)";

	private static final String sql4 = "select no,dstip from attack_path where srcip=?";
	
	private static final String sql_internal = "select internal from packet  where srcip=? and dstip=?";
	private static final String sql_vul = "select vul from risk_level where ip_addr=?";
	private static final String sql_security = "select security from risk_level where ip_addr=?";
	private static final String sql_damage = "select damage from risk_level where ip_addr=?";
	private static final String sql_com1 = "select distinct service from packet  where srcip=? and dstip=?";
	private static final String sql_com2 = "select level from com_risk_level where service=?";
	private static final String sql_com3 = "select remoteaccess from com_risk_level where service=?";
	private static final String sql_risk = "insert into path_risk_level(no, srcip, dstip, level) values(?, ?, ?, ?)";
	private static final String sql_total_risk = "select level from path_risk_level where no=?;";
	
	private static final int RISK_LEVEL=3;
	private static int MAX_RISK_LEVEL=RISK_LEVEL*4;
	
	private static final int MAX_COUNT=100;

	static Connection con = null;
	static PreparedStatement ps = null;
	static PreparedStatement ps2 = null;
	static PreparedStatement ps3 = null;
	static PreparedStatement ps4 = null;
	static PreparedStatement ps_vul = null;
	static PreparedStatement ps_security = null;
	static PreparedStatement ps_damage = null;
	static PreparedStatement ps_com1 = null;
	static PreparedStatement ps_com2 = null;
	static PreparedStatement ps_com3 = null;
	static PreparedStatement ps_internal = null;
	static PreparedStatement ps_risk = null;
	static PreparedStatement ps_total_risk = null;
	
	static String startIP = "";
	static String endPointIP = "";
	Map<String, List<String>> addedList = new HashMap<String, List<String>>();
	static Map<Integer, LinkedHashSet> attackPathList = new HashMap<Integer, LinkedHashSet>();
	int no = 0;
	static int calcCnt=0;

	CalcRiskLevel() {
		con = null;
		ps = null;
		ps2 = null;
		ps3 = null;
		Statement stmt = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");
			con = DriverManager.getConnection("jdbc:mysql://localhost/ics", "root", Const.DBPASS);

			stmt = con.createStatement();
			stmt.executeUpdate(sql0);
			stmt.executeUpdate(sql01);

			ps = con.prepareStatement(sql);
			ps2 = con.prepareStatement(sql2);
			ps3 = con.prepareStatement(sql3);
			ps4 = con.prepareStatement(sql4);
			
			ps_vul = con.prepareStatement(sql_vul);
			ps_security = con.prepareStatement(sql_security);
			ps_damage = con.prepareStatement(sql_damage);
			
			ps_com1 = con.prepareStatement(sql_com1);
			ps_com2 = con.prepareStatement(sql_com2);
			ps_com3 = con.prepareStatement(sql_com3);
			ps_internal = con.prepareStatement(sql_internal);
			ps_risk = con.prepareStatement(sql_risk);
			ps_total_risk = con.prepareStatement(sql_total_risk);
			
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} finally {
			try {
				stmt.close();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private void createAttackPath(String ipAddr) {
		// ipAddrからNW的に到達可能なホストを見つける
	
		boolean duplicated=false;
		List<String> ipList = new ArrayList<String>();

		try {
			ps.setString(1, ipAddr);
			ResultSet rs = ps.executeQuery();

			// ipAddrからNW的に到達可能なホストをリストに入れる
			while (rs.next()) {
				String dsrIP = rs.getString("dstip");
				ipList.add(dsrIP);
			}

			loop: for (String ip : ipList) {
				// ipAddrからNW的に到達可能なホストについて繰り返し
				//System.out.println(calcCnt);
				if(calcCnt>MAX_COUNT) {
					return;
				}
				calcCnt++;
				
				try {

				// ipAddrが宛先になっている攻撃パスの番号を探す
				ps2.setString(1, ipAddr);
				ResultSet rs2 = ps2.executeQuery();
				//select no from attack_path where dstip=ipAddr

				// 新しい攻撃パスであるかを確認
				// ipAddrが送信元になっている攻撃パスがあるかを確認
				ps4.setString(1, ipAddr);
				ResultSet rs4 = ps4.executeQuery();
				// select no,dstip from attack_path where srcip=ipAddr

				int myNo = 0;
				HashSet<String> ips = attackPathList.get(myNo);

				int cnt = 0;
				while (rs4.next()) {
					cnt++;
					if (ip.equals(rs4.getString("dstip"))) {
						cnt = 0;
						break;
					}
				}

				// 既存の攻撃パスとして追加
				boolean isNewAttackPath = true;
				if (cnt == 0) {
					while (rs2.next()) {

						isNewAttackPath = false;
						myNo = rs2.getInt("no");
						
						// split horizon
						/*
						if(attackPathList.get(myNo).contains(ip)) {
							// 重複するので、処理しない
							continue;
						}
						// ---------
						 * 
						 */
						
						attackPathList.get(myNo).add(ip);
						try {
							ps3.setInt(1, myNo);
							ps3.setString(2, ipAddr);
							ps3.setString(3, ip);
							ps3.executeUpdate();
						} catch (SQLIntegrityConstraintViolationException e) {
						}

					}
				}
				if (ips != null && ips.contains(endPointIP)) {
					isNewAttackPath = true;
				}
				if (isNewAttackPath) {
					// 新しい攻撃パスとして追加

					LinkedHashSet<String> orderList = new LinkedHashSet<String>();

					if (attackPathList.isEmpty()) {
						// 一番初めのパスなので新しく追加
						no++;
					} else {

						for (Iterator<Integer> iterator = attackPathList.keySet().iterator(); iterator.hasNext();) {
							// 既存の攻撃パスで、ipAddrが途中に含まれる場合は、その攻撃パスをコピーする
							int prevNo = iterator.next();
							HashSet<String> list = attackPathList.get(prevNo);
							if (list.contains(ipAddr)) {
								no++;
								for (String s : list) {
									orderList.add(s);
									if (s.equals(ipAddr)) {
										break;
									}
								}
								orderList.add(ip);
							}
						}
					}
					orderList.add(ipAddr);
					orderList.add(ip);
					attackPathList.put(no, orderList);

					try {
						ps3.setInt(1, no);
						ps3.setString(2, ipAddr);
						ps3.setString(3, ip);
						ps3.executeUpdate();
					} catch (SQLIntegrityConstraintViolationException e) {
					}

				}

				try {
					Thread.sleep(500);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				if (!ip.equals(endPointIP)) {
					createAttackPath(ip);
				} else {
					//System.out.println("EndPointIP:" + ipAddr + "," + ip);
				}
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} // end for 
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	private void calcRiskLevel(int no) {
		LinkedHashSet<String> list = attackPathList.get(no);
		String srcip="";
		String dstip="";
		for(String ip:list) {
			int isInternal=0;
			if(!srcip.isEmpty()) {
				dstip=ip;
				try {
					ps_internal.setString(1, srcip);
					ps_internal.setString(2, dstip);
					ResultSet rs = ps_internal.executeQuery();
					
					if(rs.next()) {
						isInternal=rs.getInt("internal");
					
					}
					
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				System.out.println("=============Attack path:" + no+"=============");
				System.out.println(srcip+"->"+dstip);
			} else {
				srcip=ip;
				continue;
			}
			int vul=0;
			int security_src=0;
			int security_dst=0;
			int damage=0;
			int com=0;
			int remote=0;
			ResultSet rs=null;
			try {
				if(isInternal==0) {
					
				ps_vul.setString(1, dstip);
				rs = ps_vul.executeQuery();
				if(rs.next()) {
				vul=rs.getInt("vul");
				}
				
				ps_security.setString(1, srcip);
				rs = ps_security.executeQuery();
				if(rs.next()) {
					security_src=rs.getInt("security");
				}
				ps_security.setString(1, dstip);
				rs = ps_security.executeQuery();
				if(rs.next()) {
					security_dst=rs.getInt("security");
				}
				
				ps_damage.setString(1, srcip);
				rs = ps_damage.executeQuery();
				if(rs.next()) {
					damage=rs.getInt("damage");
				}
				}
				ps_com1.setString(1, srcip);
				ps_com1.setString(2, dstip);
				rs = ps_com1.executeQuery();
				String service="";
				
				while(rs.next()) {
					service=rs.getString("service");
					ps_com2.setString(1, service);
					ResultSet rs_com = ps_com2.executeQuery();
					if(rs_com.next()) {
						com+=rs_com.getInt("level");
					}
					
					ps_com3.setString(1, service);
					ResultSet rs_com3 = ps_com3.executeQuery();
					if(rs_com3.next()) {
						remote+=rs_com3.getInt("remoteaccess");
					}
				}
				
				
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			int security=security_src+security_dst;
			if(vul>RISK_LEVEL) {
				vul=RISK_LEVEL;
			}
			if(security>RISK_LEVEL) {
				security=RISK_LEVEL;
			}
			if(com>RISK_LEVEL) {
				com=RISK_LEVEL;
			}
			if(remote>RISK_LEVEL) {
				remote=RISK_LEVEL;
			}
			/*
			System.out.println("damage level:"+damage);
			System.out.println("software vulnerability level:"+vul);
			System.out.println("vulnerable communication level:"+com);
			System.out.println("remote access level:"+remote);
			System.out.println("security level:"+security);
			*/
			double totalRiskLevel=(double)(vul+damage+com+remote-security)/MAX_RISK_LEVEL;
			System.out.println("Risk level:"+totalRiskLevel);
			
			try {
				ps_risk.setInt(1, no);
				ps_risk.setString(2, srcip);
				ps_risk.setString(3, dstip);
				ps_risk.setDouble(4, totalRiskLevel);
				ps_risk.executeUpdate();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
			
			srcip=ip;
			
		}
	}
	
	private void calcTotalRiskLevel(int no) {
		try {
			ps_total_risk.setInt(1, no);
			ResultSet rs = ps_total_risk.executeQuery();
			double totalRiskLevel=1;
			while(rs.next()) {
				double level=rs.getDouble("level");
				if(level!=0) {
					totalRiskLevel*=level;
				}
			}
			System.out.println("**********Total Risk level of path "+no+": "+totalRiskLevel+"**********");
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public static void main(String[] args) {
		startIP = args[0];
		endPointIP = args[1];

		try {
			CalcRiskLevel calcRick = new CalcRiskLevel();
			calcRick.createAttackPath(startIP);

			for (Iterator<Integer> iterator = attackPathList.keySet().iterator(); iterator.hasNext();) {
				int no = iterator.next();
				LinkedHashSet<String> list = attackPathList.get(no);
				 if (list.contains(endPointIP)) {
					 calcRick.calcRiskLevel(no);
					 calcRick.calcTotalRiskLevel(no);
				 }
				 
			}
			System.out.println("calcCnt:"+calcCnt);
			

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
