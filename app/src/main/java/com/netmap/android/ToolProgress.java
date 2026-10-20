package com.netmap.android;

import java.util.ArrayDeque;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/** Small, elapsed-time log for the current tool. Never estimates progress or completion time. */
final class ToolProgress {
    private static final Pattern ANSI=Pattern.compile("\\u001B\\[[0-?]*[ -/]*[@-~]");
    private final long started=System.nanoTime();
    private final ArrayDeque<String> lines=new ArrayDeque<>();
    private final Consumer<String> listener;
    private final String tool;
    private long lastPublish;
    ToolProgress(String tool,Consumer<String> listener){this.tool=tool;this.listener=listener;}
    static String clean(String value) {
        String text=ANSI.matcher(value==null?"":value).replaceAll("")
                .replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", "").replace('\n',' ').replace('\t',' ').trim();
        return text.length()>240?text.substring(0,240)+"…":text;
    }
    private String elapsed(){long seconds=(System.nanoTime()-started)/1_000_000_000L;return (seconds/60)+":"+String.format(java.util.Locale.ROOT,"%02d",seconds%60);}
    void event(String message){String text=clean(message);if(text.isEmpty())return;if(lines.size()==8)lines.removeFirst();lines.addLast("["+elapsed()+"] "+text);tick(false);}
    void flush(){tick(true);}
    void tick(){tick(false);}
    private void tick(boolean force){long now=System.nanoTime();if(force||now-lastPublish>=1_000_000_000L){lastPublish=now;listener.accept(text());}}
    String text(){return tool+" • Elapsed "+elapsed()+"\n"+String.join("\n",lines);}
}
