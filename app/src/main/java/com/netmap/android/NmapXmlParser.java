package com.netmap.android;

import java.io.*;import javax.xml.parsers.*;import org.w3c.dom.*;

/** Parses bounded Nmap XML into Droidmap evidence without trusting external entity content. */
final class NmapXmlParser {
    static void parse(String xml,DeviceEvidence evidence)throws Exception{
        Document doc=parseDocument(xml);NodeList hosts=doc.getElementsByTagName("host");
        for(int i=0;i<hosts.getLength();i++){Element host=(Element)hosts.item(i);String ip="";NodeList addresses=host.getElementsByTagName("address");
            for(int j=0;j<addresses.getLength();j++){Element a=(Element)addresses.item(j);String type=a.getAttribute("addrtype");if("ipv4".equals(type)||"ipv6".equals(type)){ip=a.getAttribute("addr");break;}}
            ip=evidence.resolveHost(ip);if(ip==null||ip.isEmpty())continue;NodeList names=host.getElementsByTagName("hostname");if(names.getLength()>0)evidence.add(ip,"Nmap","dnsHostname",((Element)names.item(0)).getAttribute("name"));
            for(int j=0;j<addresses.getLength();j++) {
                Element address=(Element)addresses.item(j);
                if(!"mac".equals(address.getAttribute("addrtype"))) continue;
                String mac=MacAddresses.normalize(address.getAttribute("addr"));
                if(!mac.isEmpty()) evidence.add(ip,"Nmap","macAddress",mac);
            }
            NodeList ports=host.getElementsByTagName("port");for(int j=0;j<ports.getLength();j++){Element port=(Element)ports.item(j);NodeList states=port.getElementsByTagName("state");if(states.getLength()==0||!"open".equals(((Element)states.item(0)).getAttribute("state")))continue;String number=port.getAttribute("portid");evidence.add(ip,"Nmap","openPort",number+"/"+port.getAttribute("protocol"));NodeList services=port.getElementsByTagName("service");if(services.getLength()==0)continue;Element service=(Element)services.item(0);String name=service.getAttribute("name"),product=service.getAttribute("product"),version=service.getAttribute("version");if(!name.isEmpty())evidence.add(ip,"Nmap service "+number,"serviceName",name);String banner=(product+" "+version).trim();if(!banner.isEmpty())evidence.add(ip,"Nmap service "+number,"banner",banner);}
        }
    }
    static void parseVulnerabilities(String xml,DeviceEvidence evidence,java.util.Collection<Integer> targetPorts)throws Exception{
        if(xml==null||xml.isEmpty())return;
        Document doc=parseDocument(xml);NodeList hosts=doc.getElementsByTagName("host");
        for(int i=0;i<hosts.getLength();i++){Element host=(Element)hosts.item(i);String ip="";NodeList addresses=host.getElementsByTagName("address");for(int j=0;j<addresses.getLength();j++){Element a=(Element)addresses.item(j);String type=a.getAttribute("addrtype");if("ipv4".equals(type)||"ipv6".equals(type)){ip=a.getAttribute("addr");break;}}ip=evidence.resolveHost(ip);if(ip==null||ip.isEmpty())continue;
            boolean eligible=false;
            NodeList ports=host.getElementsByTagName("port");
            for(int j=0;j<ports.getLength();j++) {
                Element port=(Element)ports.item(j);
                if(!"tcp".equals(port.getAttribute("protocol"))) continue;
                String number=port.getAttribute("portid");
                int portNumber;
                try {portNumber=Integer.parseInt(number);}catch(NumberFormatException invalid){continue;}
                if(portNumber<1||portNumber>65535||!targetPorts.contains(portNumber)) continue;
                NodeList states=port.getElementsByTagName("state");
                if(states.getLength()==0||!"open".equals(((Element)states.item(0)).getAttribute("state"))) continue;
                eligible=true;
                NodeList services=port.getElementsByTagName("service");
                if(services.getLength()>0) evidence.add(ip,"Nmap vulnerabilities","port "+number+" • service",((Element)services.item(0)).getAttribute("name"));
                recordScripts(port.getElementsByTagName("script"),ip,"port "+number,evidence);
            }
            // Host scripts (for example SMB checks) do not report a specific result port.
            if(eligible) {
                NodeList hostScripts=host.getElementsByTagName("hostscript");
                for(int j=0;j<hostScripts.getLength();j++)
                    recordScripts(((Element)hostScripts.item(j)).getElementsByTagName("script"),ip,"host-level",evidence);
            }
        }

    }
    private static Document parseDocument(String xml)throws Exception {
        if(xml==null||xml.length()>1024*1024)throw new IOException("Nmap XML is missing or too large");
        // Android's factory does not support the Xerces DTD/entity feature flags.
        // Nmap emits this bare declaration; reject all other declarations before parsing.
        xml=xml.replace("<!DOCTYPE nmaprun>","");
        if(xml.contains("<!DOCTYPE")||xml.contains("<!ENTITY"))
            throw new org.xml.sax.SAXException("Nmap XML must not contain DTD or entity declarations");
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        factory.setValidating(false);
        DocumentBuilder builder=factory.newDocumentBuilder();
        builder.setEntityResolver((publicId,systemId)->{
            throw new org.xml.sax.SAXException("External XML entities are forbidden");
        });
        Document document=builder.parse(new ByteArrayInputStream(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        if(document.getDocumentElement()==null||!"nmaprun".equals(document.getDocumentElement().getTagName()))
            throw new org.xml.sax.SAXException("Expected an Nmap XML response");
        return document;
    }

    private static void recordScripts(NodeList scripts,String ip,String scope,DeviceEvidence evidence) {
        for(int k=0;k<scripts.getLength();k++) {
            Element script=(Element)scripts.item(k);
            String id=script.getAttribute("id"),output=script.getAttribute("output");
            if(!id.isEmpty()&&!output.isEmpty()) evidence.add(ip,"Nmap vulnerabilities",scope+" • "+id,output);
        }
    }

}
