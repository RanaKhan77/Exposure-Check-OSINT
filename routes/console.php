<?php

// ============================================================================
// COMMUNITY LICENSE
// ============================================================================
// v2 "NO WALL" (2026-10-29): NO scheduled license network calls anymore.
// The daily heartbeat and weekly re-validation were removed — the default
// install makes zero unsolicited phone-home requests. Validation only runs
// when the admin explicitly activates or refreshes a key on the license
// page. (Opt-in heartbeat for the public install map: LICENSE_HEARTBEAT=on
// — see CommunityLicenseService::heartbeat().)
