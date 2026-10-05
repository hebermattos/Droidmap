package com.netmap.android;

import java.io.*;import javax.xml.parsers.*;import org.w3c.dom.*;

/** Parses bounded Nmap XML into Droidmap evidence without trusting external entity content. */
final class NmapXmlParser {
    static void parse(String xml,DeviceEvidence evidence)throws Exception{
        if(xml==null||xml.length()>1024*1024)throw new IOException("Nmap XML is too large");
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);factory.setFeature("http://xml.org/sax/features/external-general-entities",false);factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);factory.setXIncludeAware(false);factory.setExpandEntityReferences(false);
        Document doc=factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));NodeList hosts=doc.getElementsByTagName("host");
        for(int i=0;i<hosts.getLength();i++){Element host=(Element)hosts.item(i);String ip="";NodeList addresses=host.getElementsByTagName("address");
            for(int j=0;j<addresses.getLength();j++){Element a=(Element)addresses.item(j);String type=a.getAttribute("addrtype");if("ipv4".equals(type)||"ipv6".equals(type)){ip=a.getAttribute("addr");break;}}
            if(ip.isEmpty())continue;NodeList names=host.getElementsByTagName("hostname");if(names.getLength()>0)evidence.add(ip,"Nmap","dnsHostname",((Element)names.item(0)).getAttribute("name"));
            NodeList ports=host.getElementsByTagName("port");for(int j=0;j<ports.getLength();j++){Element port=(Element)ports.item(j);NodeList states=port.getElementsByTagName("state");if(states.getLength()==0||!"open".equals(((Element)states.item(0)).getAttribute("state")))continue;String number=port.getAttribute("portid");evidence.add(ip,"Nmap","openPort",number+"/"+port.getAttribute("protocol"));NodeList services=port.getElementsByTagName("service");if(services.getLength()==0)continue;Element service=(Element)services.item(0);String name=service.getAttribute("name"),product=service.getAttribute("product"),version=service.getAttribute("version");if(!name.isEmpty())evidence.add(ip,"Nmap service "+number,"serviceName",name);String banner=(product+" "+version).trim();if(!banner.isEmpty())evidence.add(ip,"Nmap service "+number,"banner",banner);}
        }
    }
    static void parseVulnerabilities(String xml,DeviceEvidence evidence)throws Exception{
        if(xml==null||xml.isEmpty())return;if(xml.length()>1024*1024)throw new IOException("Nmap vulnerability XML is too large");
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);factory.setFeature("http://xml.org/sax/features/external-general-entities",false);factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);factory.setXIncludeAware(false);factory.setExpandEntityReferences(false);
        Document doc=factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));NodeList hosts=doc.getElementsByTagName("host");
        for(int i=0;i<hosts.getLength();i++){Element host=(Element)hosts.item(i);String ip="";NodeList addresses=host.getElementsByTagName("address");for(int j=0;j<addresses.getLength();j++){Element a=(Element)addresses.item(j);String type=a.getAttribute("addrtype");if("ipv4".equals(type)||"ipv6".equals(type)){ip=a.getAttribute("addr");break;}}if(ip.isEmpty())continue;
            NodeList ports=host.getElementsByTagName("port");for(int j=0;j<ports.getLength();j++){Element port=(Element)ports.item(j);String number=port.getAttribute("portid");NodeList scripts=port.getElementsByTagName("script");for(int k=0;k<scripts.getLength();k++){Element script=(Element)scripts.item(k);String id=script.getAttribute("id"),out=script.getAttribute("output");if(!id.isEmpty()&&!out.isEmpty())evidence.add(ip,"Nmap vulnerabilities","port "+number+" • "+id,out);}}}
    }
}
