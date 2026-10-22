package com.netmap.android;

import org.json.*;

/** Bounded, endpoint-scoped projection of HTTPX JSON. Raw bodies are never persisted. */
final class HttpxResult {
    static final int MAX_LINE=65536;
    private HttpxResult() {}
    static boolean record(String line,String expectedUrl,String ip,int port,DeviceEvidence evidence) throws JSONException {
        if(line.length()>MAX_LINE)return false;
        JSONObject result=new JSONObject(line);
        if(!expectedUrl.equals(result.optString("url")) || result.optBoolean("failed")
                || result.optInt("status_code")<100 || result.optInt("status_code")>599)return false;
        String source="HTTPX tcp/"+port;
        evidence.add(ip,source,"webUrl",expectedUrl);
        evidence.add(ip,source,"httpStatus",String.valueOf(result.getInt("status_code")));
        for(String[] field:new String[][]{{"title","httpTitle"},{"webserver","server"},{"content_type","contentType"},
                {"location","redirectLocation"},{"time","responseTime"}})
            add(evidence,ip,source,field[1],result.optString(field[0]));
        JSONArray tech=result.optJSONArray("tech");
        if(tech!=null)for(int i=0;i<Math.min(tech.length(),16);i++)
            add(evidence,ip,source,"technologyEstimate",tech.optString(i));
        JSONObject tls=result.optJSONObject("tls");
        if(tls!=null)for(String field:new String[]{"tls_version","cipher","subject_cn","issuer_cn","not_before","not_after"})
            add(evidence,ip,source,field,tls.optString(field));
        return true;
    }
    private static void add(DeviceEvidence evidence,String ip,String source,String field,String value) {
        if(!value.isEmpty()&&!value.equals("null"))evidence.add(ip,source,field,value);
    }
}
