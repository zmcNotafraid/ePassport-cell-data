package com.passport.cert;

import java.io.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Certificate;

import com.passport.utils.HexUtil;

/**
 * 解析官网提供的CSCA证书
 * @author wy
 *
 */
public class CSCAMasterList {
	
	public String startFlag = "CscaMasterListData::";

	public static void main(String[] args) {
		try {
			new CSCAMasterList().analysisMasterList();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 文件是多个国家收集的其他国家的证书的汇总，都进行解析，去重。
	 * @return 
	 */
	public Map<String, Certificate> analysisMasterList() throws Exception {
		String projectPath = System.getProperty("user.dir");
		String readPath = projectPath + "/docs/ldif/icaopkd-002-ml-000159.ldif";
		String writePath = projectPath + "/docs/afterParsing/masterList/";
		String cerString = "";
		StringBuilder sb = new StringBuilder();
		Map<String, Certificate> certMaps = new HashMap<String, Certificate>();
		
		// ldif有自己的格式规范，本功能非UI展示，只解析证书不分，关系结构不解析。
		BufferedReader br = new BufferedReader(new FileReader(new File(readPath)));
		String line;
		while((line=br.readLine()) != null) {
			if(line.contains(startFlag)) {
				sb.append(line.substring(startFlag.length())); 
				while(true) {
					line = br.readLine();
					if (null == line || line.startsWith("dn:")) { //结束
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
				ASN1Primitive aP = aIn.readObject();
				ASN1Sequence aS = ASN1Sequence.getInstance(aP);
                ASN1TaggedObject aT = ASN1TaggedObject.getInstance(aS.getObjectAt(1));
                aP = ASN1Sequence.getInstance(aT.getObject().toASN1Primitive()).getObjectAt(2).toASN1Primitive();
                aS = ASN1Sequence.getInstance(aP);
                aT = ASN1TaggedObject.getInstance(aS.getObjectAt(1));
                DEROctetString derOS = (DEROctetString)(aT.getObject());
                
                bIn = new ByteArrayInputStream(HexUtil.hexStringToByteArray(derOS.toString().substring(1)));
                aIn = new ASN1InputStream(bIn);
				ArrayList<String> results =new ArrayList<>();
                while((aP = aIn.readObject()) != null) {
                	 ASN1Sequence asn1 = ASN1Sequence.getInstance(aP);
                     if (asn1 == null || asn1.size() == 0) {
                         throw new IllegalArgumentException("null or empty sequence passed.");
                     }
                     if (asn1.size() != 2) {
                         throw new IllegalArgumentException("Incorrect sequence size: " + asn1.size());
                     }
                     ASN1Set certSet = ASN1Set.getInstance(asn1.getObjectAt(1));
                     
                     for (int i = 0; i < certSet.size(); i++) {
                         Certificate certificate = Certificate.getInstance(certSet.getObjectAt(i));

                         // example: C=LT,O=ADIC under MOI,CN=CSCA,SERIALNUMBER=001
						 String issuer = certificate.getIssuer().toString();
						 Pattern pattern = Pattern.compile(".*C=([A-Z]*).*");
						 Matcher matcher = pattern.matcher(issuer);
						 String issuerHash = String.valueOf(certificate.getSubject().hashCode());
						 String serialNumber = certificate.getSerialNumber().toString();
						 String algorithm = certificate.getSignatureAlgorithm().getAlgorithm().toString();
						 String publicKey = certificate.getSubjectPublicKeyInfo().getPublicKeyData().toString();
						 if (matcher.matches()) {
							 String countryId = matcher.group(1);
							 String[] result = {issuerHash.concat(serialNumber), algorithm, publicKey, countryId };
							 results.add(String.join(",", result));
						 }
                     }
                }
				ArrayList<String> uniqueResults = new ArrayList<>();
                results.stream().distinct().forEach(result -> uniqueResults.add(result));
				FileWriter writer = new FileWriter(writePath + "master-list" + ".txt");
				for(String str: uniqueResults) {
					writer.write(str + System.lineSeparator());
				}
				writer.close();

                aIn.close();
			}

		}
		
		br.close();

		return certMaps;
	}
	
	
}

