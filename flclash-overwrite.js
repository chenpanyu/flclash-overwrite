// FlClash 电脑/安卓通用版；2026-10-14。
// 替换当前配置关联的旧覆写脚本；不要叠加全量诊断版。
// 大陆域名/大陆 IP 本地直连；境外及无法分类的请求发往指定 VPS。
// DIRECT 指设备所在地网络，人在境外时不会自动变成中国大陆出口。
// VPS 上的全部代理 TCP 出站已走 WARP；目标 UDP 仍拒绝。
function main(config) {
  const group = "境外-VPS-WARP";
  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const matching = proxies.filter(node =>
    node.server === "43.163.8.224" &&
    ["vless", "hysteria2"].includes(node.type) &&
    typeof node.name === "string" && node.name.length > 0
  );
  // 只选指定 VPS，优先 VLESS，不依赖电脑/安卓配置中的节点名称。
  const ordered = [...matching.filter(node => node.type === "vless"),
                   ...matching.filter(node => node.type === "hysteria2")];
  const selected = [...new Set(ordered.map(node => node.name))];
  if (selected.length === 0) {
    throw new Error("当前配置未发现 43.163.8.224 的 VLESS/Hysteria2 节点，不能应用此覆写");
  }

  // 境外组无 DIRECT，也不自动测速切换；默认优先 VLESS，无 VLESS 时使用 Hysteria2。
  config["proxy-groups"] = [{ name: group, type: "select", proxies: selected }];
  const provider = (behavior, url, path) => ({
    type: "http", behavior, format: "yaml", interval: 86400, url, path
  });
  config["rule-providers"] = {
    "phone-cn-domain": provider("domain",
      "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.yaml",
      "./ruleset/phone-cn-domain.yaml"),
    "phone-foreign-domain": provider("domain",
      "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
      "./ruleset/phone-foreign-domain.yaml"),
    "phone-cn-ip": provider("ipcidr",
      "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
      "./ruleset/phone-cn-ip.yaml")
  };

  // Google/AI 的识别优先于大陆域名和大陆 IP，减少地区校验流量被误分流。
  const foreignSuffixes = [
    "google.com", "google.cn", "google.com.hk", "googleapis.com", "googleapis.cn",
    "googleusercontent.com", "gstatic.com", "ggpht.com", "gvt1.com", "gvt2.com",
    "1e100.net", "googlevideo.com", "youtube.com", "ytimg.com",
    "firebaseapp.com", "firebaseio.com", "crashlytics.com", "app-measurement.com",
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai", "grok.com", "x.ai", "meta.ai", "perplexity.ai",
    "poe.com", "cursor.com", "cursor.sh", "kiro.dev", "auth0.com", "githubcopilot.com"
  ];
  config.rules = [
    // 本机及局域网是已识别的本地目标，不送往境外 VPS。
    "DOMAIN-SUFFIX,localhost,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    ...foreignSuffixes.map(domain => "DOMAIN-SUFFIX," + domain + "," + group),
    "DOMAIN,copilot.microsoft.com," + group,
    "RULE-SET,phone-foreign-domain," + group,
    "RULE-SET,phone-cn-domain,DIRECT",
    "RULE-SET,phone-cn-ip,DIRECT,no-resolve",
    // 判断失败走 VPS；无直连兜底，无原广告/服务组的可选直连。
    "MATCH," + group
  ];
  delete config["sub-rules"];

  // 延续原安卓 YAML 的 IPv4 解析设置；这不是已经确认 IPv6 泄漏。
  config.ipv6 = false;
  const localDoh = ["https://dns.alidns.com/dns-query#DIRECT", "https://doh.pub/dns-query#DIRECT"];
  const foreignDoh = ["https://1.1.1.1/dns-query#" + group, "https://1.0.0.1/dns-query#" + group];
  const policy = {};
  for (const domain of foreignSuffixes) policy["+." + domain] = foreignDoh;
  policy["copilot.microsoft.com"] = foreignDoh;
  policy["rule-set:phone-foreign-domain"] = foreignDoh;
  policy["rule-set:phone-cn-domain"] = localDoh;
  config.dns = {
    enable: true, ipv6: false, "enhanced-mode": "redir-host",
    "use-hosts": false, "use-system-hosts": false, "prefer-h3": false,
    "respect-rules": true,
    // 引导 DNS 用于解析本地 DoH 的服务器名；两个代理节点本身均为固定 IP。
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    "proxy-server-nameserver": localDoh,
    "direct-nameserver": localDoh,
    nameserver: foreignDoh,
    "nameserver-policy": policy
  };
  console.log("[desktop-mobile-split] 已应用：大陆本地直连，境外与未知目标走境外-VPS-WARP；默认优先 VLESS，无 VLESS 时使用 Hysteria2。请核对手机后续 DNS 覆写及 VPN 应用排除设置。");
  return config;
}
