package com.passport.cert;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;

import com.passport.utils.HexUtil;

/**
 * 解析官网提供的Crl列表
 * @author wy
 *
 */
public class CrlList {

	public String startFlag = "userCertificate;binary::";
	
	public static void main(String[] args) {
		try {
			List snList = new CrlList().analysisCrl();
			
			// 对比证书吊销列表，可以从对比SN的值，更严谨一些，可以对比证书Encoded的hash值
			for(int i=0; i<snList.size(); i++) {
				System.out.println(snList.get(i));
			}
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		
	}
	
	/**
	 * @return crl的SN列表
	 */
	public List analysisCrl() throws Exception {
		
		String projectPath = System.getProperty("user.dir");
		String crlReadPath = projectPath + "/docs/ldif/icaopkd-001-dsccrl-004573.ldif";
		String crlWritePath = projectPath + "/docs/afterParsing/crl/";
		String cerString = "";
		StringBuilder sb = new StringBuilder();
		List snList = new ArrayList();
		
		// ldif有自己的格式规范，本功能非UI展示，只解析证书不分，关系结构不解析。
		
		BufferedReader br = new BufferedReader(new FileReader(new File(crlReadPath)));
		String line;
		while((line=br.readLine()) != null) {
			if(line.contains(startFlag)) {
				sb.append(line.substring(startFlag.length())); 
				while(true) {
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
				ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
                Certificate certificate = Certificate.getInstance(seq);

		        String sn = HexUtil.bytesToHexString(certificate.getSerialNumber().getEncoded());
		        snList.add(sn);
		        //写文件
				FileOutputStream fos = new FileOutputStream(new File(crlWritePath + sn + ".cer"));
				fos.write(certBytes);
				fos.flush();
				fos.close();
			}

		}
		
		br.close();

		return snList;
	}
	
	
	
}
