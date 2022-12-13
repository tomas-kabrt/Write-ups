# Phishing Campaign Google Translate Trick and IPFS hosting

I spotted a new phishing campaign targeting our publicly available email boxes with some techniques I've never seen before. Let's check what the bad guys prepared for us this time :)

## Phishing email

![Alt text](Data/email.png?raw=true "Email sample")

As usual, it all started with an email. This phishing attempt claimed that you had received the document via MS OneDrive, and to open it you needed to click a button. Realistically a classic phishing email up to this point, I would rate the visual of the email 6/10 (slightly above average phishing email).

What did the link to access the document look like?

```
hxxps://u30390064[.]ct[.]sendgrid[.]net/ls/click?upn=m-2FwRkynxS1yozEugbWDlHfMogezqknwNcsV62JVAx9A-2FieGyHTKvS-2FtL6tsOxuKofldeXoLkvDF-2BnTzHPKEte
...
-2BQmIw3s7pjfh2X5183Wkt3CtduA5afgEDK5R7KUtW0mgszGWEUzC57VPHX-2FAb3PPKm5kdMzwVJfK7XR94wj03mo2F-2Fo
```

It pointed to Send Grid, which is a legitimate mail service that large companies use to send emails, monitor click-throughs and manage email subscriptions. Such encoding makes it difficult for the victim to evaluate the email because the link has no apparent connection to the target website.

In the same email, there were also links to Unsubscribe and Manage. That supports the theory that the campaign was using legitimate services to give their campaign more credibility. On the other hand, I have to credit Send Grid for how quickly they took down the link after reporting. Such a response is not a standard with other providers.

**Small side note:** I don't understand email service companies that hide the destination URL. I would encourage all users to ignore such emails rather than blindly clicking on any link. Links from some companies can be decoded using publicly available tools (often directly from the vendor), but I haven't found any easy way for Send Grid. Does anyone have any tips?

## Following the link into the translated world

As I mentioned, I was unable to extract the link from the Send Grid URL, so I took the easy route and just followed the link in an isolated VM and the redirect took me here:

```
https://ipfs-io.translate.goog/ipfs/QmWt2RQvZNRkfiHLuqRMmiEWhUE69jkVnvfZh5C9EGc8WK?filename=result202bili_cham-e068.html&_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp#abcde@sumup.pl
```

That is interesting. `translate.goog` is owned by Google and is used for full-page translation by the Google Translate service. It took me a bit to understand what the attackers were trying to achieve. Then it hit me, that it might be a cheap and easy method to overcome web/gateway filtering. How does Google Translate help you do that?

### Google Translate URL link

Google Translate allows you to translate the entire web page simply by passing it a link that redirects you to a new URL where the original domain is hyphenated and inserted as a subdomain of `translate.goog`. The rest of the original URL request (subdirectory, path, parameters) is also added to the `translate.goog` request with additional parameters for the translation service.

![Alt text](Data/google_translate.png?raw=true "Email sample")

Using this logic, the destination URL in our case was `hxxps://ipfs[.]io/ipfs/QmWt2RQvZNRkfiHLuqRMmiEWhUE69jkVnvfZh5C9EGc8WK?filename=result202bili_cham-e068.html#abcde@sumup.pl`.

### Google Translate Network Flow

The second important point to understand is how Google Translate works from a network perspective. Do you think that the web page you want to translate is first visited by your browser and then the text is transferred to Google for translation? Wrong, you are just communicating with Google and Google accesses the web page for you, translates it and return it to you with translated text. When you are navigating on the translated website, the URL path is updated accordingly. It seems that Google Translate can be used as an easy tool to bypass web filtering.

The trick is that the domain belongs to Google and not all filtering services have the courage to include URLs from Google's domain in their block list. By trial and error, I noticed that Google Translate uses the URL reputation information from Google Safe Browsing and returns an error when accessing a page reported in the program. Let’s do quick tests using Virus Total and see how different security products are dealing with those.

![VT Results](Data/vt_results.png?raw=true)

As you can see, not many of them are marking Google Translate URLs to a malicious website as malicious. I recommend you check your security solution and its behaviour with those types of URL links.

Is your employer blocking access to your favourite social network? Just go through Google Translate. Is your phishing target's traffic being monitored for suspicious URLs? Just send links in phishing emails through Google Translate.

Disclaimer: Please do not go to your favourite social network via Google Translate. HTTPS connection is established with Google, so they can decrypt your connection and view your traffic using passwords.

Another interesting thing was that the attackers managed to hide the Google Translate menu, which also added a bit more credibility. Normally you need to click the minimize button in the top right corner, but in my case, the menu was hidden from the first visit.

![Alt text](Data/phishing_page.png?raw=true "Email sample")

### Phishing webpage served via IPFS

We are slowly getting to the end, but it is still not all. The goal of the phishing website is to obtain your login credentials and use them later in a follow-up attack. The website has a similar quality to a phishing email, but there are a few interesting features.

Based on the fragment identifier (#) in the URL, the domain part of the victim's email address is used for the portal name, in the text box and footer, and it also dynamically loaded the correct favicon based on the original web page. These small details can make all the difference.

The last interesting part is the hosting of the phishing site via IPFS (InterPlanetary File System). Haven't heard of IPFS and wondering what it is? It is a distributed file system for storing and accessing files, websites, applications and data, where anyone who accesses the resource also becomes, at least temporarily, a file provider. This ensures that when the file is accessed, it will continue to live on the network. The more popular the file, the more nodes share it. File addressing is based on the file hash. If the file is changed, a new address is also assigned. For detailed technical information, I recommend their documentation: https://docs.ipfs.tech/concepts/what-is-ipfs/#decentralizationAs.

Circling back to the URL we have seen during the campaign, we can say that the web page is saved on the IPFS network. Normally you would need to go via their IPFS protocol, but it is also possible for ease of use to go via IPFS Gateway - for example: `https://ipfs.io/ipfs/[hash_of_the_file]`.

![Alt text](Data/IPFS.png?raw=true "Email sample")

One of the main reasons IPFS has become a new tool for fraudsters is that many web hosting or cloud services now offer IPFS services. This brings more flexibility with new types of phishing URLs that don't have such a bad reputation yet. IPFS gateway providers are also legitimate companies like Cloudflare (list of available IPFS gateways https://ipfs.github.io/public-gateway-checker/) and links to these gateways are also usually not blocked through URL reputation. Last but not least, taking down content from a distributed system is significantly harder compared to the HTTP world.

## Conclusion

It is not often that a single phishing campaign uses several new techniques at once. This campaign may need a little more love to take it to another level, but technically it has brought a lot of interesting techniques that we will hear about in 2023.

![Phishing Diagram](Data/diagram.png?raw=true)

I particularly liked leveraging trust in Google Translate to overcome reputation filtering and the use of distributed file sharing to host malicious payloads. There is still room for the use of techniques by attackers to be more convincing. Even so, both techniques are quite difficult to reliably detect and the main share of responsibility will remain on the end users.

The use of distributed file systems (e.g. IPFS) has certainly not had the last word. The adoption those technologies is increasing day by day and with it the ease of use for the average user. For example, the web browser Brave can work with IPFS directly. In my opinion, fraudulent clones of legit web pages to steal credentials hosted on IPFS can become a nightmare due to the complex takedown process.

## Prevention

- As always the best thing is to promote awareness in a light and easily digestible form
- Report all malicious URLs via the Google Safe Browsing program
- Monitor or block access to the IPFS network

## Reading and References
