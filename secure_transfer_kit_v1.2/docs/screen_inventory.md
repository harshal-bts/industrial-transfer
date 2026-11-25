# Operator screen crosswalk — v1.2

All 26 PNGs are conceptual UI mockups from the guide. The interactive simulator implements the corresponding states in a shared, simplified interface; production integration and exact screen implementation remain open.

| ID | Screen | Image | Demonstration behavior |
|---|---|---|---|
| SCR-01 | Login | [PNG](../visuals/operator_screens/01_login.png) | Credential gate |
| SCR-02 | Job selection | [PNG](../visuals/operator_screens/02_select.png) | Select configured example job |
| SCR-03 | Network preflight | [PNG](../visuals/operator_screens/03_netcheck.png) | Network checks |
| SCR-04 | Network progress | [PNG](../visuals/operator_screens/04_netprogress.png) | Network work units / controls |
| SCR-05 | Awaiting server commit | [PNG](../visuals/operator_screens/05_netpending.png) | Explicit pending server decision |
| SCR-06 | Network complete | [PNG](../visuals/operator_screens/06_netdone.png) | Simulated commit |
| SCR-07 | USB quick health check | [PNG](../visuals/operator_screens/07_usbcheck.png) | USB export preflight |
| SCR-08 | USB export progress | [PNG](../visuals/operator_screens/08_usbprogress.png) | USB export work units |
| SCR-09 | USB export complete | [PNG](../visuals/operator_screens/09_usbexported.png) | Export only; transport to Part B |
| SCR-10 | USB import preflight | [PNG](../visuals/operator_screens/10_usbimportcheck.png) | USB read-only and network checks |
| SCR-11 | USB import progress | [PNG](../visuals/operator_screens/11_usbimportprogress.png) | Import work units |
| SCR-12 | Server receipt | [PNG](../visuals/operator_screens/12_usbcommit.png) | Simulated commit |
| SCR-13 | USB cleanup authorization | [PNG](../visuals/operator_screens/13_cleanup.png) | Part B cleanup review only |
| SCR-14 | Returned receipt | [PNG](../visuals/operator_screens/14_return.png) | Return / acknowledge |
| SCR-15 | Paused | [PNG](../visuals/operator_screens/15_paused.png) | Pause |
| SCR-16 | Stopped safely | [PNG](../visuals/operator_screens/16_stopped.png) | Safe stop |
| SCR-17 | Restart recovery | [PNG](../visuals/operator_screens/17_recovery.png) | Re-authenticate in same process |
| SCR-18 | Failed mandatory check | [PNG](../visuals/operator_screens/18_failure.png) | Failed check blocks |
| SCR-19 | Transfer history | [PNG](../visuals/operator_screens/19_history.png) | Read-only history |
| SCR-20 | Transfer details | [PNG](../visuals/operator_screens/20_details.png) | Read-only details |
| SCR-21 | Safe sign-out | [PNG](../visuals/operator_screens/21_signout.png) | Stop then sign out |
| SCR-22 | Authentication error | [PNG](../visuals/operator_screens/22_loginerror.png) | Wrong password / lockout |
| SCR-23 | Dataset inventory | [PNG](../visuals/operator_screens/23_inventory.png) | Fixed sample inventory |
| SCR-24 | Connection interrupted | [PNG](../visuals/operator_screens/24_disconnect.png) | Simulated disconnect / repeat checks |
| SCR-25 | Server quarantine | [PNG](../visuals/operator_screens/25_quarantine.png) | Reject / no cleanup |
| SCR-26 | USB cleanup result | [PNG](../visuals/operator_screens/26_cleaned.png) | Simulated cleanup, no deletion |
