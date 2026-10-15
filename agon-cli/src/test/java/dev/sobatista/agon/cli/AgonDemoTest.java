package dev.sobatista.agon.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgonDemoTest {

    @Test
    void theWholeCompetitionRunsVerifiesAndDetectsTampering() {
        AgonDemo.Result r = new AgonDemo().run();

        // red = bob's SQL (60) + bob's XSS (40); blue = dave's buffer overflow (80).
        assertEquals(100, r.byGroup().get("red"));
        assertEquals(80, r.byGroup().get("blue"));
        assertEquals(100, r.byHacker().get("bob"));

        assertTrue(r.verified(), "the genuine scoreboard verifies against the arbiter's key");
        assertTrue(r.tamperDetected(), "a flipped reward is rejected by verification");
    }
}
