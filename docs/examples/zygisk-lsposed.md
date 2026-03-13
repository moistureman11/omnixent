# Using Omnixent with Zygisk and LSPosed

[Zygisk](https://github.com/topjohnwu/Magisk) is the Magisk-in-Zygote feature that lets Magisk modules inject code directly into the Android Zygote process, while [LSPosed](https://github.com/LSPosed/LSPosed) is a modern implementation of the Xposed Framework built on top of Zygisk that lets you install and run Xposed-style modules on a rooted Android device.

Omnixent lets you discover **what people are actively searching for** related to these tools across multiple search engines and platforms. This can help you:

- Track trending topics and questions in the Android modding community
- Identify common issues users face with Zygisk and LSPosed
- Find popular modules, guides, and tutorials that people are looking for
- Monitor how interest in these tools evolves over time

---

## Public API (no authentication required)

The public endpoint queries **Google** search suggestions and requires no API key.

```sh
curl "https://your-omnixent-host/v1/public?term=zygisk"
```

```sh
curl "https://your-omnixent-host/v1/public?term=lsposed"
```

**Example response:**

```json
{
  "success": true,
  "cached": false,
  "result": [
    {
      "category": "questions",
      "originalTerm": "zygisk",
      "term": "how to install zygisk",
      "result": [
        "how to install zygisk modules",
        "how to install zygisk on android",
        "how to enable zygisk in magisk"
      ]
    },
    {
      "category": "comparisons",
      "originalTerm": "zygisk",
      "term": "zygisk vs",
      "result": [
        "zygisk vs magisk hide",
        "zygisk vs riru",
        "zygisk vs shamiko"
      ]
    }
  ]
}
```

---

## Private API (authentication required)

The private endpoint supports all available search engines and accepts an `x-omnixent-auth` header (API key or JWT token).

### Search across multiple engines

**Google** – general search suggestions:

```sh
curl "https://your-omnixent-host/v1/private?term=lsposed&service=google&language=en&country=us" \
  -H "x-omnixent-auth: YOUR_API_KEY"
```

**YouTube** – video tutorial and walkthrough searches:

```sh
curl "https://your-omnixent-host/v1/private?term=lsposed&service=youtube&language=en&country=us" \
  -H "x-omnixent-auth: YOUR_API_KEY"
```

**DuckDuckGo** – privacy-focused search suggestions:

```sh
curl "https://your-omnixent-host/v1/private?term=zygisk&service=duckduckgo&language=en&country=us" \
  -H "x-omnixent-auth: YOUR_API_KEY"
```

**Bing** – Microsoft search suggestions:

```sh
curl "https://your-omnixent-host/v1/private?term=zygisk module&service=bing&language=en&country=us" \
  -H "x-omnixent-auth: YOUR_API_KEY"
```

### Combine results for deeper insights

You can call the API multiple times with different services and aggregate the results to build a comprehensive picture of what the community is searching for:

```js
const services = ['google', 'youtube', 'bing', 'duckduckgo'];
const terms = ['zygisk', 'lsposed'];

for (const service of services) {
  for (const term of terms) {
    const res = await fetch(
      `https://your-omnixent-host/v1/private?term=${term}&service=${service}&language=en&country=us`,
      { headers: { 'x-omnixent-auth': process.env.OMNIXENT_API_KEY } }
    );
    const data = await res.json();
    console.log(`[${service}] "${term}":`, data.result);
  }
}
```

### Use a JWT token instead of an API key

```sh
curl "https://your-omnixent-host/v1/private?term=lsposed module&service=google&language=en&country=us" \
  -H "x-omnixent-auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

## Check which services are available

```sh
curl "https://your-omnixent-host/v1/availability"
```

```json
{
  "success": true,
  "result": ["google", "amazon", "duckduckgo", "bing", "youtube"]
}
```

---

## Further reading

- [Omnixent README](../../README.md)
- [Magisk / Zygisk documentation](https://topjohnwu.github.io/Magisk/)
- [LSPosed repository](https://github.com/LSPosed/LSPosed)
