package org.pcap4j.sample;

import java.sql.*;
import java.util.*;
import javax.net.ssl.SSLContext;
import java.io.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.apache.http.Header;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.json.JSONObject;

public class UpdateVul {

	private static final String sql = "select cve from vul";
	private static final String sql_ip = "select cve from vul where ip_addr=?";
	private static final String sql_update = "update vul set rce=1 where cve=?";
	private static final String sql_update2 = "update vul set poc=1 where cve=?";
	private static final String sql_update3 = 
			"update vul set attack_com=?, attack_vector=?, privilege=?, user_interact=?,availability=?, integrity=? where cve=?";
	private static final String PCAP_FILE_DIR = "src/main/resources/nvd/";
	private static final String POC_1 = "proof-of-concept";
	private static final String POC_3 = "exploit";
	private static final String POC_4 = ".py";
	private static final String POC_5 = "proofofconcept";
	private static final String POC_6 = "proof_of_concept";
	private static final String URL_EXPLOITDB="https://www.exploit-db.com/search?cve=";
	
	static Connection con = null;
	static PreparedStatement ps = null;
	static PreparedStatement ps2 = null;
	static PreparedStatement ps3 = null;
	static PreparedStatement ps_ip = null;
	
	String[] pocs = { POC_1, POC_3 , POC_4, POC_5, POC_6};

	UpdateVul() {
		con = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");
			con = DriverManager.getConnection("jdbc:mysql://localhost/ics", "root", Const.DBPASS);
			ps = con.prepareStatement(sql_update);
			ps2 = con.prepareStatement(sql_update2);
			ps3 = con.prepareStatement(sql_update3);
			ps_ip = con.prepareStatement(sql_ip);

		} catch (Exception e) {
			e.printStackTrace();

		}
	}

	private void getVulInfo(String ip) {
		Statement stmt = null;
		try {
			ResultSet rs =null;
			if(ip.isEmpty()) {
				stmt = con.createStatement();
				rs = stmt.executeQuery(sql);
			} else {
				ps_ip.setString(1, ip);
				rs = ps_ip.executeQuery();
			}
			while (rs.next()) {
				String cve = rs.getString("cve");
				int[] result = this.readNVD(cve);
				int rce = result[0];
				int poc = result[1];
				if (rce == 1) {
					ps.setString(1, cve);
					ps.executeUpdate();
					System.out.println(cve + ":rce:" + rce);
				}
				if (poc == 1) {
					ps2.setString(1, cve);
					ps2.executeUpdate();
					System.out.println(cve + ":poc:" + poc);
				}
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (stmt != null) {
				try {
					stmt.close();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

	}

	private int[] readNVD(String cve) {
		int[] result = { 0, 0 };
		File dir = new File(PCAP_FILE_DIR);
		File[] files = dir.listFiles();
		for (File file : files) {
			String filename = file.getName();
			if (filename.endsWith(".json")) {
				ObjectMapper mapper = new ObjectMapper();
				try {
					JsonNode root = mapper.readTree(file);
					for (JsonNode n : root.get("CVE_Items")) {
						String cve_j = n.get("cve").get("CVE_data_meta").get("ID").asText();
						if (!cve_j.equals(cve)) {
							continue;
						}
						
						
						String attackComplexity = n.get("impact").get("baseMetricV3").get("cvssV3").get("attackComplexity").asText();
						String attackVector = n.get("impact").get("baseMetricV3").get("cvssV3").get("attackVector").asText();
						String privilegesRequired = n.get("impact").get("baseMetricV3").get("cvssV3").get("privilegesRequired").asText();
						String userInteraction = n.get("impact").get("baseMetricV3").get("cvssV3").get("userInteraction").asText();
						String integrityImpact = n.get("impact").get("baseMetricV3").get("cvssV3").get("integrityImpact").asText();
						String availabilityImpact = n.get("impact").get("baseMetricV3").get("cvssV3").get("availabilityImpact").asText();
						
						if(attackComplexity.equals("LOW")) {
							attackComplexity="L";
							ps3.setString(1,attackComplexity);
						}
						if(attackVector.equals("NETWORK")) {
							attackVector="N";
							ps3.setString(2,attackVector);
						}
						if(privilegesRequired.equals("NONE")) {
							privilegesRequired="N";
							ps3.setString(3,privilegesRequired);
						}
						if(userInteraction.equals("NONE")) {
							userInteraction="N";
							ps3.setString(4,userInteraction);
						}
						if(integrityImpact.equals("HIGH")) {
							integrityImpact="H";
							ps3.setString(5,integrityImpact);
						}
						if(availabilityImpact.equals("HIGH")) {
							availabilityImpact="H";
							ps3.setString(6,availabilityImpact);
						}
						
						ps3.setString(7,cve);
						ps3.executeUpdate();
						
						String desc = n.get("cve").get("description").get("description_data").get(0).get("value")
								.asText();
						if (desc.toLowerCase().contains("remote code execution")||desc.contains("RCE")) {
							result[0] = 1;
						}
						if(this.getPoC(cve)==1) {
							result[1] = 1;
							return result;
						}
						for (JsonNode ref : n.get("cve").get("references").get("reference_data")) {
							String poc = ref.get("url").asText();
							for (String keyword : pocs) {
								if (poc.toLowerCase().contains(keyword)) {
									result[1] = 1;
									System.out.println(poc);
									return result;
								}
							}
						}
						return result;
					}
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return result;
				}
			}
		}
		return result;
	}
	
	private int getPoC(String cve) {
		
		String cve_exploitdb=cve.split("-")[1];
		HttpGet request = new HttpGet(URL_EXPLOITDB+cve_exploitdb);
		CloseableHttpClient httpClient=null;
		int poc=0;
		try {
			RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectTimeout(5000)          
                    .build();
			
			List<Header> header = new ArrayList<Header>();
			header.add(new BasicHeader("User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:77.0)"));
			header.add(new BasicHeader("Accept","application/json, text/javascript, */*; q=0.01"));
		    header.add(new BasicHeader("Accept-Language", "en-US,en;q=0.5"));
		    header.add(new BasicHeader("X-Requested-With","XMLHttpRequest"));
		    header.add(new BasicHeader("Connection", "close"));
		    
			 SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy(){
		            public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		                return true;
		            }}
		        ).build();
		        httpClient = HttpClientBuilder.create()
		                        .setSslcontext(sslContext)
		                        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
		                        .setDefaultRequestConfig(requestConfig)
		                        .setDefaultHeaders(header)
		                        .build();
			 
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		HttpResponse response;
		StringBuilder builder = new StringBuilder();
		try {
			response = httpClient.execute(request);
			int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode != 200) {
            	return poc;
            }
			HttpEntity entity = response.getEntity();
			InputStream content = entity.getContent();
	        if (content == null) {
	        	return poc;
	        }
	        BufferedReader reader = new BufferedReader(new InputStreamReader(content));
            String line;
            while ((line = reader.readLine()) != null) {
            	builder.append(line);
            }
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}         
		try {
			JSONObject json = new JSONObject(builder.toString());
			int cnt=json.getInt("recordsTotal");     
			if(cnt>0) {
				poc=1;
				System.out.println(builder.toString());
			}
            
        } catch (Exception e) {
            e.printStackTrace();
        }
		
		return poc;
	}

	public static void main(String[] args) {
		String ip="";
		if(args.length>0) {
			ip=args[0];
		}
		try {
			UpdateVul u = new UpdateVul();
			u.getVulInfo(ip);
		} finally {
			if (con != null) {
				try {
					con.close();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}

}
