package com.passport.cert;

import java.io.*;
import java.util.ArrayList;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * 解析官网提供的Crl列表
 * @author wy
 *
 */
public class CrlList {

	public String startFlag = "userCertificate;binary::";
	
	public static void main(String[] args) {
		try {
			new CrlList().analysisCrl();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * @return crl的SN列表
	 */
	public ArrayList analysisCrl() throws Exception {
		String projectPath = System.getProperty("user.dir");
		String crlReadPath = projectPath + "/docs/ldif/icaopkd-001-dsccrl-004573.ldif";
		String crlWritePath = projectPath + "/docs/afterParsing/crl/";
		String cerString = "";
		StringBuilder sb = new StringBuilder();
		ArrayList<String> snList = new ArrayList<>();

		// ldif有自己的格式规范，本功能非UI展示，只解析证书不分，关系结构不解析。

		BufferedReader br = new BufferedReader(new FileReader(new File(crlReadPath)));
		String line;
		while ((line = br.readLine()) != null) {
			if (line.contains(startFlag)) {
				sb.append(line.substring(startFlag.length()));
				while (true) {
					line = br.readLine();
					if (line.startsWith("sn:")) { //结束
						break;
					} else {
						sb.append(line);
					}
				}
				cerString = sb.toString();
				sb.delete(0, sb.length());

				// 解析证书文件，base64格式解码
				byte[] certBytes = Base64.getDecoder().decode(cerString.replaceAll("\\s*", ""));
				ByteArrayInputStream bIn = new ByteArrayInputStream(certBytes);
				ASN1InputStream aIn = new ASN1InputStream(bIn);
				ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
				Certificate certificate = Certificate.getInstance(seq);
				String issuerHash = String.valueOf(certificate.getSubject().hashCode());
				String serialNumber = certificate.getSerialNumber().toString();
				snList.add(issuerHash.concat(serialNumber));
			}
		}

		br.close();

		FileWriter writer = new FileWriter(crlWritePath + "cr-list" + ".txt");
		for (String str : snList) {
			writer.write(str + System.lineSeparator());
		}
		writer.close();

		return snList;
	}
}
