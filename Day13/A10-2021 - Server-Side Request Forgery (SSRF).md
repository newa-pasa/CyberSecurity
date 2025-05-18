# A10:2021 - Server-Side Request Forgery (SSRF)

**What it is:**
Server-Side Request Forgery (SSRF) vulnerabilities occur when a web application fetches a remote resource (e.g., by making an HTTP request to a URL) based on user-supplied input, without properly validating that input. This allows an attacker to coerce the server-side application to send a crafted request to an unintended destination. These destinations can be internal services within the organization's network (which are not normally accessible from the internet) or external third-party systems.

**Common Types / How it Works:**
*   **Accessing Internal Services:** An attacker provides a URL that points to an internal IP address or hostname.
    *   Example: `http://example.com/fetch?url=http://127.0.0.1/admin` or `http://example.com/fetch?url=http://192.168.1.10/internal_api`
*   **Scanning Internal Networks:** Attackers can use SSRF to map out internal networks by sending requests to various internal IP addresses and ports and observing the server's responses or response times.
*   **Interacting with Cloud Provider Metadata Services:** Cloud platforms (like AWS, Azure, GCP) often have metadata services accessible via special IP addresses (e.g., `169.254.169.254` in AWS). SSRF can be used to query these services and potentially retrieve sensitive information like instance credentials.
*   **Exploiting Other Services:** The vulnerable server can be used as a proxy to send malicious requests to other internal or external services, potentially exploiting vulnerabilities in those services.
*   **Bypassing Firewalls:** Since the request originates from the trusted server, it might bypass firewall rules that would block direct external access.
*   **Using Different URL Schemes:** Attackers might use schemes like `file:///` to read local files, `gopher://` to interact with various TCP-based services, or `dict://`.

**Potential Impact:**
*   Information disclosure (e.g., internal network topology, service banners, sensitive data from internal services, cloud credentials).
*   Interaction with and potential compromise of internal services (e.g., databases, admin interfaces).
*   Denial of service against internal or external systems.
*   Bypassing access controls and firewalls.
*   Remote Code Execution on internal systems if the SSRF can trigger a vulnerability in another service.

**Basic Prevention:**
*   **Network Segmentation:** Isolate the functionality that makes outbound requests. The server making these requests should have limited network access to only necessary internal and external resources.
*   **Input Validation and Sanitization (Primary Defense):**
    *   **Whitelist Approach:** Maintain a strict whitelist of allowed protocols (e.g., only `http`, `https`), domains, IP addresses, and ports that the application is permitted to request. Deny all other requests.
    *   **URL Parsing and Validation:** Carefully parse and validate the user-supplied URL. Be aware of bypass techniques (e.g., DNS rebinding, URL encoding, redirects).
    *   Do not rely solely on blacklist approaches as they are often incomplete.
*   **Disable Unused URL Schemes:** Explicitly allow only necessary URL schemes (e.g., `http`, `https`). Disallow potentially dangerous schemes like `file://`, `gopher://`, `ftp://`, `dict://` unless absolutely required and properly secured.
*   **Response Handling:**
    *   Do not send the raw response body from the requested remote resource back to the client. Only extract and display the necessary information in a safe way. This can prevent leaking sensitive information from internal services.
*   **Use Dedicated Network Policies:** Configure network policies (e.g., firewall rules) for the application server to restrict its outbound connections to only legitimate and necessary destinations.
*   **Authentication for Internal Services:** Ensure internal services require authentication, even if they are not directly exposed to the internet.
*   **Avoid Sending Raw User Input Directly to Request Libraries:** Process and validate user input before using it to construct a request.