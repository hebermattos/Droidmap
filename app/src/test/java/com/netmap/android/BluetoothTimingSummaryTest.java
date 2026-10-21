package com.netmap.android;

import org.junit.Test;
import java.util.List;
import static org.junit.Assert.*;

public class BluetoothTimingSummaryTest {
    @Test public void nearestActiveDeadlineWinsOverFinishedOrUnlimitedTimers() {
        var finished=new BluetoothTimings.Snapshot("sdp",30,30000,0,"finished");
        var unlimited=new BluetoothTimings.Snapshot("gatt",0,1000,-1,"running");
        var read=new BluetoothTimings.Snapshot("read",30,10000,20000,"running");
        var retry=new BluetoothTimings.Snapshot("retry",2,1000,1000,"running");
        assertSame(retry,BluetoothTimingSummary.current(List.of(finished,unlimited,read,retry)));
        assertSame(retry,BluetoothTimingSummary.current(List.of(retry,read,unlimited,finished)));
    }
    @Test public void unlimitedAndStoppedStatesDoNotCreateFakeCountdowns() {
        var timer=new BluetoothTimings.Snapshot("discovery",0,120000,-1,"running");
        assertSame(timer,BluetoothTimingSummary.current(List.of(timer)));
        assertTrue(BluetoothTimings.describe(timer).contains("No limit"));
        assertNull(BluetoothTimingSummary.current(List.of(new BluetoothTimings.Snapshot("read",30,30000,0,"timed_out"))));
        assertNull(BluetoothTimingSummary.current(List.of()));
    }
}
