package com.passport.cert;

import java.io.*;
import java.util.ArrayList;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * Parse Crl list
 */
public class CrlList {

	public static void main(String[] args) {
		try {
			analysisCrl();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	public static void analysisCrl() throws Exception {
		String startFlag = "userCertificate;binary::";
		String projectPath = System.getProperty("user.dir");
		String crlReadPath = projectPath + "/docs/ldif/icaopkd-001-dsccrl-004573.ldif";
		String crlWritePath = projectPath + "/docs/afterParsing/crl/";
		String cerString;
		StringBuilder sb = new StringBuilder();
		ArrayList<String> snList = new ArrayList<>();

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
	}
}
