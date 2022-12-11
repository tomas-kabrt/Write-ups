# Phishing Campaign Google Translate Trick

I spotted a new phishing campaign targeting our publicly available email boxes with some techniques I have never seen before. Let's check what the bad guys prepared for us this time :)

## Phishing email

![Alt text](data/email.png?raw=true "Email sample")

It all started classically with an email. Phishing attempt claiming that you received the document via MS OneDrive and to view the documents, you have to follow the link. So far, it is quite normal. I would give the visual of the email 6/10 (above average phishing email).

So what did the link to access the document looked like?

```
hxxps://u30390064[.]ct[.]sendgrid[.]net/ls/click?upn=m-2FwRkynxS1yozEugbWDlHfMogezqknwNcsV62JVAx9A-2FieGyHTKvS-2FtL6tsOxuKofldeXoLkvDF-2BnTzHPKEte
...
-2BQmIw3s7pjfh2X5183Wkt3CtduA5afgEDK5R7KUtW0mgszGWEUzC57VPHX-2FAb3PPKm5kdMzwVJfK7XR94wj03mo2F-2Fo
```

It pointed to Send Grid, which is a legitimate mailing service used by big companies to send emails, track clicks and manage email subscriptions. This makes the email evaluation by the user a little bit harder as this link doesn't bear any obvious connection to the target webpage.

In the same email, you could also find links to Unsubscribe and to Manage, which just supports the theory that the campaign were using legitimate services to give their campaign more credibility. On the other hand, I have to give Send Grid a small praise, that they took down the links within a few days since reporting. It is not so common with other providers.

```
A little side note: I do not understand those companies for email services, which hide the destination URL. I would recommend all users to just ignore such emails rather than blindly click. With some such companies, you can decode the destination URL from the link, but for Send Grid, I couldn't find any easy way. Does anyone have some tips?
```

## Following the link into the translated world

As I said I was not able to extract the link from the Send Grid URL, so I went the hard way and just followed the link in an isolated VM and the redirect took me here:

```
https://ipfs-io.translate.goog/ipfs/QmWt2RQvZNRkfiHLuqRMmiEWhUE69jkVnvfZh5C9EGc8WK?filename=result202bili_cham-e068.html&_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=wapp#abcde@sumup.pl
```

That is interesting. `translate.goog` is owned by Google and is used for full-page translation by the Google Translate service. It took me a bit to understand what the attackers were trying to achieve. Then it hit me, that it might be a cheap and easy method to overcome web/gateway filtering. How does Google Translate help you achieve that? Let's have a look.

### Google Translate URL

First, we need to understand how the Google Translate URL works. When you want to translate the whole page with Google Translate, the service creates a subdomain from the TLD and SLD of the page you want to translate and the `.` is changed to the `-`. The rest of the URL (subdirectory, path, parameters) is also added to the `translate.goog` request with some additional parameters for the translating service.

![Alt text](data/google_translate.png?raw=true "Email sample")

Getting the target URL with this knowledge is easy and if you receive any such link with Google Translate, you should check directly it. Also if you are lazy, just open the URL in a safe environment, open the web page source code and the target URL is at the 4th line ;)

In our case, the target URL is `hxxps://ipfs[.]io/ipfs/QmWt2RQvZNRkfiHLuqRMmiEWhUE69jkVnvfZh5C9EGc8WK?filename=result202bili_cham-e068.html#abcde@sumup.pl`

### Google Translate Network Flow

The second important point to understand is how Google Translate works from the network perspective. Do you think, the website you want to translate is first accessed by your browser and then the text for translation is transferred to Google? Wrong, you are just communicating with Google service, and it grabs the webpage for you, translates it and serves it back to you. Are you thinking what I am thinking? Google Translate can be used as an easy web filtering bypass tool. Is your employer blocking access to your favourite social network, no problem, just go via Google Translate. Is your phishing target traffic being monitored and blocked for suspicious URLs? Just send the links in the phishing emails through Google Translate.

**Disclaimer:** Please don't go to your favourite social network via Google Translate. The HTTPS is established with Google, so they can decrypt the connection and see your traffic with passwords.

The trick here is that the TLD and SLD belong to Google and practically no one will have the courage to put this into their block list. The only filtering that is done by Google Translate seems to be based on Google Safe Browsing. When I tried to translate the webpage reported in the program, I got an error. You can test your antivirus and your filtering product, but for me, it worked as an easy bypass tool.

Another interesting fact was that the attackers managed to hide the Google Translate menu, which added also a bit more credibility. Normally you need to click on the minimise button in the top right corner, but in this case, it was hidden since the first visit.

![Alt text](data/phishing_page.png?raw=true "Email sample")

### Phishing webpage served via IPFS

We are slowly getting to the end, but it is still not all. The phishing web page's objective is to get your credentials and utilise those later in some sort of consequent attack. The webpage has a similar quality as the phishing email, but there are a few interesting touches.

Based on the fragment identifier (#) in the URL, the domain part of the victim email address is used for the name of the portal, in the text box, and the footer, and it also dynamically loads the right favicon based on the original website. Small things like this can make a difference.

The last interesting part is hosting the phishing website via IPFS. You might be asking what the hell is IPFS? As per their words: **InterPlanetary File System is a distributed system for storing and accessing files, websites, applications, and data**.

What does it mean? It is distributed file system, where everyone who accesses the resource becomes at least temporarily also the provider of the file. By this, it is ensured that when the file is accessed, it will continue to live on. The more popular the file, the more nodes share it.

The file address is based on the hash of the file. If the file is changed, a new address is also assigned. If you want to know more, I recommend you to read the deep explanation on their website: https://docs.ipfs.tech/concepts/what-is-ipfs/#decentralizationAs.

Circling back to the malicious URL we have seen used during the campaign, we can see what is going on. The file is saved on the IPFS network. Normally you would need to go via their protocol, but they also offer the ability to use an IPFS Gateway and simply go via `https://ipfs.io/ipfs/[hash_of_the_file]`.

![Alt text](data/IPFS.png?raw=true "Email sample")

One of the main reasons why IPFS has become a new tool for fraudsters is that many web hosting or cloud services are now offering IPFS services. This brings more flexibility with new types of phishing URLs, that do not have a bad reputation yet. Also, the providers of the IPFS gateways are legitimate companies like Cloudflare and the links are not also being blocked by URL reputation scanners. And lastly taking down content from the distributed system is considerably harder in comparison to the HTTP world.

## Conclusion

It's not often seen that one phishing campaign is bringing multiple new techniques to the table. This one would still need little love to push in on another level, but the technical part was interesting, and I would say that we will hear about some of those techniques in 2023.

I especially like leveraging trust in Google Translate to get over reputation filtering and usage of distributed file sharing for hosting malicious payload. Both concepts are relatively hard to reliably detect and the main portion of responsibility will be on end-users. There is still room to make both techniques more believable from the attacker's side.

I also see other malicious usages of IPFS and similar concepts of distributed file systems. The adaptation of this technology is growing (Brave browser for example can work with IPFS directly) and with it the ease of use for regular users. And for example, cloned fraudulent websites on IPFS can become a nightmare.

## Prevention

- As always the best thing is to promote awareness in a light and easily digestible form to all employees
- Report all malicious URLs via the Google Safe Browsing program
- Monitor or block access to the IPFS network

## Reading and References
