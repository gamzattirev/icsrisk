package org.pcap4j.sample;

import java.sql.*;
import java.util.*;

import javax.net.ssl.SSLContext;

import java.io.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;

import org.pcap4j.sample.HttpClientFactory;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import org.apache.http.Header;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;

public class UpdateVul {

	private static final String sql = "select cve from vul";
	private static final String sql_update = "update vul set rce=1 where cve=?";
	private static final String sql_update2 = "update vul set poc=1 where cve=?";
	private static final String PCAP_FILE_DIR = "src/main/resources/";
	private static final String POC_1 = "proof-of-concept";
	//private static final String POC_2 = "poc";
	private static final String POC_3 = "exploit";
	private static final String POC_4 = ".py";
	private static final String POC_5 = "proofofconcept";
	private static final String POC_6 = "proof_of_concept";
	private static final String URL_EXPLOITDB="https://www.exploit-db.com/exploits";
	
	static Connection con = null;
	static PreparedStatement ps = null;
	static PreparedStatement ps2 = null;
	String[] pocs = { POC_1, POC_3 , POC_4, POC_5, POC_6};

	UpdateVul() {
		con = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");
			con = DriverManager.getConnection("jdbc:mysql://localhost/ics", "root", Const.DBPASS);
			ps = con.prepareStatement(sql_update);
			ps2 = con.prepareStatement(sql_update2);

		} catch (Exception e) {
			e.printStackTrace();

		}
	}

	private void getVulInfo() {
		Statement stmt = null;
		try {
			stmt = con.createStatement();
			ResultSet rs = stmt.executeQuery(sql);
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
						String desc = n.get("cve").get("description").get("description_data").get(0).get("value")
								.asText();
						if (desc.toLowerCase().contains("remote code execution")||desc.contains("RCE")) {
							result[0] = 1;
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
		
		HttpGet request = new HttpGet(URL_EXPLOITDB);
		//CloseableHttpClient httpclient =HttpClients.createDefault();
		CloseableHttpClient httpClient=null;
		try {
			RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectTimeout(1000)          // コネクションタイムアウト
                    //.setSocketTimeout(10000)        // 通信タイムアウト
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
		try {
			response = httpClient.execute(request);
			HttpEntity entity = response.getEntity();
			System.out.println(response.getStatusLine().getStatusCode());
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}         
        

		int poc=0;
		
		return poc;
	}

	private int getRCE(String cve) {
		int rce = 0;

		return rce;
	}

	public static void main(String[] args) {
		try {
			UpdateVul u = new UpdateVul();
			/*
			u.getVulInfo();
			*/
			u.getPoC("");
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