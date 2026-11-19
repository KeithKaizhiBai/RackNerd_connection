# WireGuard on iPhone

Use a separate client key pair and a dedicated tunnel address for each phone. Keep the generated profile on trusted devices. A profile or its QR code contains a private key.

## Import

After the server administrator confirms enrollment, AirDrop the profile to your own iPhone. Open the official WireGuard app and choose **Add a tunnel → Create from file or archive**. Select the profile and approve the VPN permission. Remove the transfer copy from Files and Recently Deleted after import. Disconnect other VPN apps during testing.

## Verify

Record ordinary connectivity on Wi-Fi and cellular before enabling the tunnel. On each network, check the WireGuard handshake, load a new Safari page, use a networked app, and compare the reported IPv4 address with the expected gateway exit. Check DNS resolution and the resolver reported by a DNS leak test. For an IPv4-only exit, test on an IPv6-capable access network and confirm that a native IPv6 address is no longer visible through an IPv6-only endpoint. Switch networks and repeat. Disable the tunnel and verify ordinary connectivity returns.

## Remove

Switch off the phone tunnel and remove it from WireGuard. Have the administrator revoke that device's public key and remove its device-specific persistent configuration. Other clients can stay connected.
