package com.netmap.android;

import javax.xml.parsers.*;

/** Models Android's unsupported factory features; parsing delegates to the host JDK. */
public final class AndroidDocumentBuilderFactory extends DocumentBuilderFactory {
    private final DocumentBuilderFactory delegate=DocumentBuilderFactory.newDefaultInstance();
    @Override public DocumentBuilder newDocumentBuilder()throws ParserConfigurationException {
        delegate.setNamespaceAware(isNamespaceAware());
        delegate.setValidating(isValidating());
        return delegate.newDocumentBuilder();
    }
    @Override public Object getAttribute(String name){throw new IllegalArgumentException(name);}
    @Override public void setAttribute(String name,Object value){throw new IllegalArgumentException(name);}
    @Override public boolean getFeature(String name)throws ParserConfigurationException {throw new ParserConfigurationException(name);}
    @Override public void setFeature(String name,boolean value)throws ParserConfigurationException {throw new ParserConfigurationException(name);}
    @Override public void setXIncludeAware(boolean value){throw new UnsupportedOperationException("XInclude");}
}
