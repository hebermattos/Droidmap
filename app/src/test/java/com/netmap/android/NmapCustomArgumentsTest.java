package com.netmap.android;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.*;

public class NmapCustomArgumentsTest {
    @Test public void diagnosticFlagsRemainAvailable() {
        assertEquals(Arrays.asList("--reason", "-vv"),
                NmapCommands.checkedCustomArgs(Arrays.asList("--reason", "-vv")));
        assertTrue(NmapCommands.checkedCustomArgs(Collections.emptyList()).isEmpty());
    }

    @Test public void rejectsOverridesAndTargets() {
        for (String option : Arrays.asList("--script", "--script=exploit", "-p", "-Pn",
                "-sS", "--datadir", "-oX", "--version-all", "192.168.0.2",
                "--reason=1", "--", "--max-retries")) {
            try {
                NmapCommands.checkedCustomArgs(Collections.singletonList(option));
                fail("Accepted unsafe option: " + option);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("Unsupported"));
            }
        }
    }

    @Test public void rejectsExcessiveArguments() {
        String[] args = new String[17];
        Arrays.fill(args, "-v");
        try {
            NmapCommands.checkedCustomArgs(Arrays.asList(args));
            fail("Accepted too many arguments");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Too many"));
        }
    }
}
