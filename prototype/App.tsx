import React, { useState, useEffect, useRef } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { motion, AnimatePresence } from "framer-motion";
import {
  Anchor,
  Search,
  X,
  ShieldCheck,
  AlertTriangle,
  Skull,
  Info,
  Clock,
  History,
  LifeBuoy,
  Navigation,
  Waves,
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const queryClient = new QueryClient();

interface CheckResult {
  name: string;
  description: string;
  flag: boolean;
  weight: number;
}

interface AnalysisResult {
  checks: CheckResult[];
  flaggedCount: number;
  riskScore: number;
  verdict: "safe" | "suspicious" | "phishing";
  url: string;
}

// US10: Demonstration-only blocklist.
// Replace with a maintained threat-intelligence source before production.
// .test domains are reserved for testing, not real phishing domains.
const KNOWN_BAD_DOMAINS = new Set(["malicious.example.test"]);

const KNOWN_BAD_URLS = new Set(["https://malicious.example.test/login"]);

const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "goo.gl",
  "t.co",
  "ow.ly",
  "buff.ly",
  "adf.ly",
  "rb.gy",
  "short.io",
  "tiny.cc",
  "is.gd",
  "cli.gs",
  "pic.gd",
  "dwarfurl.com",
  "yfrog.com",
  "migre.me",
  "ff.im",
  "url4.eu",
  "doiop.com",
  "tr.im",
  "twit.ac",
]);

function analyzeUrl(url: string): AnalysisResult {
  const input = url.trim();
  let parsedUrl: URL;

  try {
    // Reject ambiguous or malformed inputs rather than allowing URL() to repair them.
    if (!input || /\s/.test(input) || input.includes("\\")) {
      throw new Error("Invalid URL");
    }
    // A supplied scheme must be HTTP(S); never rewrite ftp:// or javascript:.
    const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(input);
    if (hasScheme && !/^https?:\/\//i.test(input)) {
      throw new Error("Unsupported URL scheme");
    }
    const normalized = hasScheme ? input : `https://${input}`;
    parsedUrl = new URL(normalized);

    // A hostname must be a reasonable DNS name or IP, not an incomplete label.
    const host = parsedUrl.hostname.replace(/\.$/, "");
    const validDnsName =
      host.length <= 253 &&
      host.includes(".") &&
      host.split(".").every((label) =>
        label.length > 0 && label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
      );
    const validIpAddress = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) &&
      host.split(".").every((part) => Number(part) <= 255);
    const validIpv6 = host.startsWith("[") && host.endsWith("]");
    if (
      !["http:", "https:"].includes(parsedUrl.protocol) ||
      !(validDnsName || validIpAddress || validIpv6) ||
      (hasScheme && !/^https?:\/\/[^/]+/i.test(input))
    ) {
      throw new Error("Invalid URL");
    }
  } catch {
    throw new Error("That URL looks like bad bait, try again!");
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/\.$/, "");
  const path = parsedUrl.pathname;
  const search = parsedUrl.search;
  const fullUrl = parsedUrl.href;
  const rawPathAndQuery = input.split(/[?#]/)[0];

  const knownBadDomain = [...KNOWN_BAD_DOMAINS].some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );

  // Remove fragment; it does not affect the server destination.
  const comparableUrl = new URL(fullUrl);
  comparableUrl.hash = "";
  const knownBadUrl = KNOWN_BAD_URLS.has(comparableUrl.href);

  const isKnownBad = knownBadDomain || knownBadUrl;

  const encodedMatches = input.match(/%[0-9a-f]{2}/gi) || [];

  const redirectParams = [
    "redirect",
    "redirect_uri",
    "return_url",
    "goto",
    "next",
    "url",
    "link",
  ];

  const hasRedirect = [...parsedUrl.searchParams.keys()].some((key) =>
    redirectParams.includes(key.toLowerCase()),
  );

  // Preserve the 12 original checks, now with severity weights.
  const checks: CheckResult[] = [
    {
      name: "IP Address as Host",
      description: "A numeric IP address is used instead of a domain name.",
      flag: /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname),
      weight: 15,
    },
    {
      name: "Suspicious TLD",
      description:
        "This domain ending warrants additional caution, but is not proof of phishing.",
      flag: /\.(tk|ml|ga|cf|gq|xyz|top|click|download|loan|work|party|gdn|win|review|stream|date|faith|racing|kim|science|country|bid|trade|loans|accountant|webcam|video|men|women|cheap)$/i.test(
        hostname,
      ),
      weight: 5,
    },
    {
      name: "Excessive Subdomains",
      description:
        "Multiple nested subdomains may obscure the registered domain.",
      flag: hostname.split(".").length > 4,
      weight: 5,
    },
    {
      name: "Brand Impersonation",
      description:
        "The hostname contains patterns associated with brand impersonation.",
      flag: /(paypa1|g00gle|amaz0n|faceb00k|micros0ft|apple-id|bankofamerica-|secure-paypal|account-verify|login-secure)/i.test(
        hostname,
      ),
      weight: 25,
    },
    {
      name: "Excessive URL Length",
      description:
        "An unusually long URL may conceal important destination details.",
      flag: input.length > 75,
      weight: 5,
    },
    {
      name: "Phishing Keywords",
      description:
        "The URL contains terms sometimes associated with credential theft.",
      flag:
        /(login|signin|verify|account|secure|update|confirm|banking|password|credential|authenticate|wallet|recovery|suspended)/i.test(
          path + search + hostname,
        ) &&
        !/^(?:.+\.)?(google\.com|microsoft\.com|apple\.com|amazon\.com|facebook\.com|github\.com|youtube\.com)$/.test(
          hostname,
        ),
      weight: 10,
    },
    {
      name: "No HTTPS",
      description: "The URL uses HTTP instead of encrypted HTTPS.",
      flag: parsedUrl.protocol !== "https:",
      weight: 5,
    },
    {
      name: "URL Shortener",
      description:
        "This shortened link hides its final destination. The destination has not been verified.",
      flag: SHORTENERS.has(hostname),
      weight: 5,
    },
    {
      name: "@ Symbol in URL",
      description:
        "An @ symbol in URL credentials can disguise the actual destination.",
      flag: Boolean(parsedUrl.username || parsedUrl.password),
      weight: 15,
    },
    {
      name: "Redirect Parameters",
      description:
        "The URL contains a parameter that could redirect the visitor.",
      flag: hasRedirect,
      weight: 10,
    },
    {
      name: "Character Encoding",
      description:
        "Multiple encoded characters may make the URL harder to inspect.",
      flag: encodedMatches.length > 3,
      weight: 10,
    },
    {
      name: "URL Anomalies",
      description: "Unusual double slashes were found within the URL path.",
      flag:
        /\/\//.test(parsedUrl.pathname) ||
        (rawPathAndQuery.includes("\\") &&
          !/^https?:\/\//i.test(rawPathAndQuery)),
      weight: 5,
    },
  ];

  // US10: Additional known-bad list check.
  checks.push({
    name: "Known-Bad URL/Domain",
    description: isKnownBad
      ? "This URL or domain matches the configured known-bad list."
      : "No match in the configured local list. This does not guarantee safety.",
    flag: isKnownBad,
    weight: 100,
  });

  const flaggedCount = checks.filter((check) => check.flag).length;

  const weightedTotal = checks
    .filter((check) => check.flag)
    .reduce((sum, check) => sum + check.weight, 0);

  const riskScore = Math.min(100, weightedTotal);

  // Verdicts are determined by severity, not check count.
  let verdict: "safe" | "suspicious" | "phishing";

  const hasBrandImpersonation = checks.some(
    check => check.name === "Brand Impersonation" && check.flag
  );

  const hasPhishingKeywords = checks.some(
    check => check.name === "Phishing Keywords" && check.flag
  );

  const highConfidencePhishing =
    hasBrandImpersonation && hasPhishingKeywords;

  if (isKnownBad || highConfidencePhishing || riskScore >= 50) {
    verdict = "phishing";
  } else if (riskScore >= 25) {
    // Four coincidental 5-point signals alone should not elevate a URL.
    verdict = "suspicious";
  } else {
    verdict = "safe";
  }

  return {
    checks,
    flaggedCount,
    riskScore,
    verdict,
    url: input,
  };
}

/* Realistic teal fish — Blue Tang style, faces RIGHT */
function TealFishSvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 130 60"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
      style={{ overflow: "visible" }}
    >
      <defs>
        <radialGradient id="tf-body" cx="55%" cy="42%" r="50%">
          <stop offset="0%" stopColor="#3ed4bf" />
          <stop offset="55%" stopColor="#1a9e8e" />
          <stop offset="100%" stopColor="#0d6659" />
        </radialGradient>
        <radialGradient id="tf-belly" cx="50%" cy="30%" r="60%">
          <stop offset="0%" stopColor="#a8f0e8" stopOpacity="0.7" />
          <stop offset="100%" stopColor="#a8f0e8" stopOpacity="0" />
        </radialGradient>
        <linearGradient id="tf-tail" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#0a4d43" />
          <stop offset="100%" stopColor="#0d7a6a" />
        </linearGradient>
      </defs>
      {/* Caudal (tail) fin — forked */}
      <path
        d="M22,30 C14,18 4,12 2,8 C8,20 10,30 8,30 C10,30 8,40 2,52 C4,48 14,42 22,30 Z"
        fill="url(#tf-tail)"
      />
      {/* Anal fin (bottom rear) */}
      <path
        d="M44,46 Q36,56 30,58 Q38,52 42,48 Z"
        fill="#0d7a6a"
        opacity="0.85"
      />
      {/* Body */}
      <path
        d="M22,30 C28,14 50,6 80,10 C104,13 120,20 124,30 C120,40 104,47 80,50 C50,54 28,46 22,30 Z"
        fill="url(#tf-body)"
      />
      {/* Belly sheen */}
      <path
        d="M40,38 C52,30 76,28 104,34 C90,28 62,26 40,38 Z"
        fill="url(#tf-belly)"
      />
      {/* Dorsal fin — tall, natural curve */}
      <path
        d="M50,10 C56,2 68,0 80,2 C88,4 92,8 90,12 C80,10 62,10 50,10 Z"
        fill="#0d7a6a"
        opacity="0.9"
      />
      {/* Pectoral fin */}
      <path
        d="M76,30 C68,24 60,32 64,42 C68,36 76,36 76,30 Z"
        fill="#12907e"
        opacity="0.8"
      />
      {/* Lateral line */}
      <path
        d="M44,22 Q70,18 100,22"
        stroke="#0a5548"
        strokeWidth="0.8"
        fill="none"
        strokeDasharray="3,3"
        opacity="0.6"
      />
      {/* Gill plate */}
      <path
        d="M92,14 Q88,30 92,46"
        stroke="#0a5548"
        strokeWidth="1.2"
        fill="none"
        strokeLinecap="round"
        opacity="0.7"
      />
      {/* Eye — small, dark, realistic */}
      <circle cx="112" cy="24" r="5" fill="#0a1a18" />
      <circle cx="112" cy="24" r="3.2" fill="#0d2e2a" />
      <circle cx="110.5" cy="22.5" r="1" fill="rgba(255,255,255,0.55)" />
      {/* Mouth slit */}
      <path
        d="M126,29 Q128,31 126,33"
        stroke="#0a5548"
        strokeWidth="1"
        fill="none"
        strokeLinecap="round"
      />
    </svg>
  );
}

/* Realistic striped tropical fish — Sergeant Major / Convict Tang style, faces RIGHT */
function TropicalFishSvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 110 72"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
      style={{ overflow: "visible" }}
    >
      <defs>
        <radialGradient id="trp-body" cx="50%" cy="45%" r="55%">
          <stop offset="0%" stopColor="#e8993c" />
          <stop offset="55%" stopColor="#c47530" />
          <stop offset="100%" stopColor="#8a4f18" />
        </radialGradient>
        <radialGradient id="trp-belly" cx="50%" cy="25%" r="65%">
          <stop offset="0%" stopColor="#f5c880" stopOpacity="0.65" />
          <stop offset="100%" stopColor="#f5c880" stopOpacity="0" />
        </radialGradient>
        <clipPath id="trp-clip">
          <path d="M16,36 C22,14 40,4 64,6 C88,8 104,20 106,36 C104,52 88,64 64,66 C40,68 22,58 16,36 Z" />
        </clipPath>
      </defs>
      {/* Tail — slightly fan-shaped */}
      <path
        d="M18,36 C10,22 0,14 2,10 C8,22 10,36 8,36 C10,36 8,50 2,62 C0,58 10,50 18,36 Z"
        fill="#6e3610"
      />
      {/* Anal fin */}
      <path
        d="M34,62 Q26,70 22,72 Q30,66 36,64 Z"
        fill="#6e3610"
        opacity="0.85"
      />
      {/* Ventral fin */}
      <path
        d="M48,64 Q44,72 40,74 Q46,68 52,66 Z"
        fill="#8a4f18"
        opacity="0.8"
      />
      {/* Body */}
      <path
        d="M16,36 C22,14 40,4 64,6 C88,8 104,20 106,36 C104,52 88,64 64,66 C40,68 22,58 16,36 Z"
        fill="url(#trp-body)"
      />
      {/* Vertical dark stripes — clipped to body */}
      <g clipPath="url(#trp-clip)">
        <rect
          x="24"
          y="0"
          width="10"
          height="80"
          fill="#4a2408"
          opacity="0.55"
        />
        <rect
          x="46"
          y="0"
          width="9"
          height="80"
          fill="#4a2408"
          opacity="0.45"
        />
        <rect
          x="66"
          y="0"
          width="8"
          height="80"
          fill="#4a2408"
          opacity="0.35"
        />
        <rect
          x="84"
          y="0"
          width="7"
          height="80"
          fill="#4a2408"
          opacity="0.25"
        />
      </g>
      {/* Belly sheen */}
      <path
        d="M36,46 C48,36 76,34 100,40 C84,34 54,32 36,46 Z"
        fill="url(#trp-belly)"
      />
      {/* Dorsal fin — tall, segmented look */}
      <path
        d="M36,6 C44,0 56,-2 70,0 C82,2 92,8 90,12 C76,8 56,8 36,6 Z"
        fill="#6e3610"
        opacity="0.9"
      />
      {/* Pectoral fin */}
      <path
        d="M80,34 C72,24 62,30 66,44 C70,36 80,40 80,34 Z"
        fill="#9a5a20"
        opacity="0.8"
      />
      {/* Gill plate arc */}
      <path
        d="M96,16 Q92,36 96,56"
        stroke="#5a2e0a"
        strokeWidth="1.3"
        fill="none"
        strokeLinecap="round"
        opacity="0.7"
      />
      {/* Lateral line */}
      <path
        d="M38,22 Q64,18 92,24"
        stroke="#5a2e0a"
        strokeWidth="0.8"
        fill="none"
        strokeDasharray="2.5,3"
        opacity="0.5"
      />
      {/* Eye — iris ring */}
      <circle cx="102" cy="28" r="5" fill="#120800" />
      <circle cx="102" cy="28" r="3.5" fill="#2a1000" />
      <circle cx="100.8" cy="26.8" r="0.9" fill="rgba(255,255,255,0.5)" />
      {/* Mouth */}
      <path
        d="M108,36 Q110,38 108,40"
        stroke="#5a2e0a"
        strokeWidth="1"
        fill="none"
        strokeLinecap="round"
      />
    </svg>
  );
}

/* Realistic puffer fish — faces RIGHT */
function PufferFishSvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 90 76"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
      style={{ overflow: "visible" }}
    >
      <defs>
        <radialGradient id="pf-body" cx="46%" cy="44%" r="52%">
          <stop offset="0%" stopColor="#6db86e" />
          <stop offset="55%" stopColor="#4a8c52" />
          <stop offset="100%" stopColor="#2d5c35" />
        </radialGradient>
        <radialGradient id="pf-belly" cx="50%" cy="30%" r="58%">
          <stop offset="0%" stopColor="#c8e8c0" stopOpacity="0.6" />
          <stop offset="100%" stopColor="#c8e8c0" stopOpacity="0" />
        </radialGradient>
      </defs>
      {/* Tail fin — stubby and rounded */}
      <path
        d="M16,38 C8,28 0,24 2,20 C6,28 8,38 6,38 C8,38 6,48 2,56 C0,52 8,48 16,38 Z"
        fill="#2d5c35"
      />
      {/* Body — inflated oval */}
      <ellipse cx="52" cy="38" rx="34" ry="30" fill="url(#pf-body)" />
      {/* Belly sheen */}
      <ellipse cx="54" cy="46" rx="20" ry="16" fill="url(#pf-belly)" />
      {/* Spines — thin, sharp, distributed around top half */}
      <line
        x1="36"
        y1="8"
        x2="34"
        y2="1"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <line
        x1="46"
        y1="5"
        x2="45"
        y2="-2"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <line
        x1="56"
        y1="5"
        x2="56"
        y2="-2"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <line
        x1="66"
        y1="8"
        x2="68"
        y2="1"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <line
        x1="74"
        y1="16"
        x2="78"
        y2="10"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <line
        x1="84"
        y1="28"
        x2="89"
        y2="24"
        stroke="#254d2c"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <line
        x1="84"
        y1="48"
        x2="89"
        y2="52"
        stroke="#254d2c"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <line
        x1="74"
        y1="60"
        x2="78"
        y2="66"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <line
        x1="60"
        y1="67"
        x2="60"
        y2="74"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <line
        x1="46"
        y1="68"
        x2="45"
        y2="75"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <line
        x1="32"
        y1="64"
        x2="30"
        y2="71"
        stroke="#254d2c"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      {/* Pectoral fin — small */}
      <path
        d="M56,46 C48,40 42,50 48,58 C50,52 58,52 56,46 Z"
        fill="#3d7444"
        opacity="0.8"
      />
      {/* Dorsal fin — small ridge */}
      <path
        d="M44,8 C50,4 60,4 66,8 C60,8 50,8 44,8 Z"
        fill="#2d5c35"
        opacity="0.9"
      />
      {/* Spot pattern on body */}
      <circle cx="42" cy="28" r="2.5" fill="#2d5c35" opacity="0.3" />
      <circle cx="58" cy="24" r="2" fill="#2d5c35" opacity="0.25" />
      <circle cx="70" cy="32" r="1.8" fill="#2d5c35" opacity="0.25" />
      <circle cx="50" cy="44" r="2" fill="#2d5c35" opacity="0.2" />
      {/* Gill line */}
      <path
        d="M62,16 Q58,38 62,58"
        stroke="#2d5c35"
        strokeWidth="1"
        fill="none"
        strokeLinecap="round"
        opacity="0.65"
      />
      {/* Eye — smaller, realistic */}
      <circle cx="74" cy="32" r="5.5" fill="#0e1e10" />
      <circle cx="74" cy="32" r="3.8" fill="#182e1a" />
      <circle cx="72.8" cy="30.8" r="1" fill="rgba(255,255,255,0.5)" />
      {/* Beak/mouth — small and pursed */}
      <path
        d="M86,38 Q88,40 86,43"
        stroke="#254d2c"
        strokeWidth="1.2"
        fill="none"
        strokeLinecap="round"
      />
      <ellipse cx="86" cy="40" rx="2" ry="3" fill="#3d7444" opacity="0.5" />
    </svg>
  );
}

function AppContent() {
  const [url, setUrl] = useState("");
  const [isCasting, setIsCasting] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [bubbles, setBubbles] = useState<
    { id: number; left: string; duration: string; delay: string }[]
  >([]);

  useEffect(() => {
    const savedHistory = localStorage.getItem("phishfinder_history");
    if (savedHistory) {
      try {
        setHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error("Failed to load history");
      }
    }

    // Generate random bubbles
    const newBubbles = Array.from({ length: 15 }).map((_, i) => ({
      id: i,
      left: `${Math.random() * 100}%`,
      duration: `${5 + Math.random() * 10}s`,
      delay: `${Math.random() * 5}s`,
    }));
    setBubbles(newBubbles);
  }, []);

  const saveToHistory = (newUrl: string) => {
    const updatedHistory = [
      newUrl,
      ...history.filter((h) => h !== newUrl),
    ].slice(0, 5);
    setHistory(updatedHistory);
    localStorage.setItem("phishfinder_history", JSON.stringify(updatedHistory));
  };

  const handleCast = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setError(null);
    setResult(null);
    setIsCasting(true);

    // Simulate analysis delay for effect
    setTimeout(() => {
      try {
        const analysis = analyzeUrl(url);
        setResult(analysis);
        saveToHistory(url);
      } catch (err: any) {
        setError(err.message || "Failed to analyze URL");
      } finally {
        setIsCasting(false);
      }
    }, 1500);
  };

  const clearInput = () => {
    setUrl("");
    setResult(null);
    setError(null);
  };

  return (
    <div className="min-h-screen relative flex flex-col font-sans">
      {/* Swimming fish layer */}
      <TealFishSvg className="bg-fish fish-teal-1" />
      <TealFishSvg className="bg-fish fish-teal-2" />
      <TropicalFishSvg className="bg-fish fish-tropical-1" />
      <TropicalFishSvg className="bg-fish fish-tropical-2" />
      <PufferFishSvg className="bg-fish fish-puffer-1" />
      <PufferFishSvg className="bg-fish fish-puffer-2" />
      {/* Background ambient elements */}
      {bubbles.map((bubble) => (
        <div
          key={bubble.id}
          className="bubble w-4 h-4"
          style={{
            left: bubble.left,
            animationDuration: bubble.duration,
            animationDelay: bubble.delay,
          }}
        />
      ))}
      {/* Header / Hero */}
      <header className="relative pt-16 pb-32 px-6 flex flex-col items-center justify-center text-center overflow-hidden bg-sidebar-primary border-b-2 border-secondary/20 shadow-lg">
        <div className="relative z-20 flex flex-col items-center">
          <Anchor className="w-16 h-16 text-secondary mb-4 drop-shadow-[0_0_10px_rgba(20,200,200,0.5)] animate-[bob_4s_ease-in-out_infinite]" />
          <h1 className="font-pirata text-6xl md:text-8xl tracking-wider text-foreground glow-text mb-2">
            PhishGuard
          </h1>
          <p className="text-xl text-muted-foreground max-w-lg mx-auto font-mono tracking-wide">
            Don't fall for phishing links. Paste your URL below to test the
            waters.
          </p>
        </div>

        {/* Animated Waves */}
        <div className="wave-container">
          <svg
            className="wave wave-1"
            viewBox="0 0 1440 80"
            preserveAspectRatio="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M0,40 C180,10 360,70 540,40 C720,10 900,70 1080,40 C1260,10 1350,60 1440,40 L1440,80 L0,80 Z"
              fill="rgba(20,110,160,0.35)"
            />
          </svg>
          <svg
            className="wave wave-2"
            viewBox="0 0 1440 80"
            preserveAspectRatio="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M0,50 C200,20 400,75 600,50 C800,25 1000,70 1200,48 C1300,36 1380,55 1440,50 L1440,80 L0,80 Z"
              fill="rgba(10,60,110,0.5)"
            />
          </svg>
        </div>
      </header>
      {/* Main Content Area */}
      <main className="flex-1 relative z-20 -mt-16 px-4 md:px-8 max-w-5xl mx-auto w-full flex flex-col gap-12 pb-24">
        {/* Input Area */}
        <section className="wood-texture p-6 md:p-10 rounded-2xl relative z-30 transform transition-all duration-300 hover:scale-[1.01]">
          <form onSubmit={handleCast} className="relative">
            <div className="flex flex-col md:flex-row gap-4 items-center">
              <div className="relative flex-1 w-full group">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <Navigation
                    className={`w-6 h-6 transition-colors duration-300 ${url ? "text-secondary" : "text-muted-foreground"}`}
                  />
                </div>
                <Input
                  type="text"
                  placeholder="Paste a suspicious URL here (e.g. http://secure-login.paypa1.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="fishing-rod-input h-16 pl-12 pr-12 text-lg font-mono bg-background border-2 border-border rounded-xl w-full focus-visible:ring-0 focus-visible:ring-offset-0 text-foreground placeholder:text-muted-foreground/50"
                  disabled={isCasting}
                />
                {url && (
                  <button
                    type="button"
                    onClick={clearInput}
                    className="absolute inset-y-0 right-0 pr-4 flex items-center text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <X className="w-6 h-6" />
                  </button>
                )}
              </div>
              <Button
                type="submit"
                disabled={isCasting || !url.trim()}
                className="h-16 px-8 text-xl font-pirata tracking-wider bg-secondary hover:bg-secondary/90 text-secondary-foreground rounded-xl w-full md:w-auto shadow-[0_0_15px_rgba(20,200,200,0.3)] hover:shadow-[0_0_25px_rgba(20,200,200,0.5)] transition-all flex gap-3 border-b-4 border-r-4 border-secondary-foreground/20 active:border-b-0 active:border-r-0 active:translate-y-1 active:translate-x-1"
              >
                {isCasting ? (
                  <>
                    <Search className="w-6 h-6 animate-spin" />
                    Scanning Waters...
                  </>
                ) : (
                  <>
                    <Anchor className="w-6 h-6" />
                    Cast the Line
                  </>
                )}
              </Button>
            </div>

            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="absolute -bottom-12 left-0 right-0 text-center text-destructive font-mono bg-destructive/10 py-2 rounded-lg border border-destructive/30"
                >
                  <AlertTriangle className="inline w-5 h-5 mr-2 -mt-1" />
                  {error}
                </motion.div>
              )}
            </AnimatePresence>
          </form>
        </section>

        {/* Results Panel */}
        <AnimatePresence>
          {result && (
            <motion.section
              initial={{ opacity: 0, y: 100 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 50 }}
              transition={{ type: "spring", damping: 20, stiffness: 100 }}
              className="wood-texture p-6 md:p-8 rounded-2xl overflow-hidden relative"
            >
              {/* Decorative scan line */}
              <div
                className="absolute top-0 left-0 w-full h-1 bg-secondary/50 animate-[sonar-sweep_3s_linear_infinite]"
                style={{ transformOrigin: "left center" }}
              ></div>

              <div className="flex flex-col md:flex-row gap-8 items-start">
                {/* Overall Verdict & Sonar */}
                <div className="w-full md:w-1/3 flex flex-col items-center border-b md:border-b-0 md:border-r border-border pb-8 md:pb-0 md:pr-8">
                  <div className="relative w-48 h-48 rounded-full border-4 border-border flex items-center justify-center mb-6 sonar-grid overflow-hidden shadow-[inset_0_0_20px_rgba(0,0,0,0.5)]">
                    <div
                      className="absolute inset-0 border-[10px] border-transparent rounded-full"
                      style={{
                        borderColor:
                          result.verdict === "safe"
                            ? "hsl(120 80% 40% / 0.5)"
                            : result.verdict === "suspicious"
                              ? "hsl(var(--warning) / 0.5)"
                              : "hsl(var(--destructive) / 0.5)",
                      }}
                    ></div>

                    <div className="relative z-10 flex flex-col items-center">
                      <span
                        className="text-5xl font-mono font-bold"
                        style={{
                          color:
                            result.verdict === "safe"
                              ? "hsl(120 80% 40%)"
                              : result.verdict === "suspicious"
                                ? "hsl(var(--warning))"
                                : "hsl(var(--destructive))",
                        }}
                      >
                        {result.riskScore}
                      </span>
                      <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest mt-1">
                        Risk Score
                      </span>
                    </div>

                    {/* Needle */}
                    <div
                      className="absolute top-1/2 left-1/2 w-1 h-24 origin-top transition-transform duration-1000 ease-out"
                      style={{
                        backgroundColor:
                          result.verdict === "safe"
                            ? "hsl(120 80% 40%)"
                            : result.verdict === "suspicious"
                              ? "hsl(var(--warning))"
                              : "hsl(var(--destructive))",
                        transform: `rotate(${180 + (result.riskScore / 100) * 180}deg)`,
                        marginTop: "-1px",
                        marginLeft: "-2px",
                      }}
                    ></div>
                  </div>

                  <div className="text-center">
                    <h2
                      className={`font-pirata text-4xl mb-2 flex items-center justify-center gap-3 ${
                        result.verdict === "safe"
                          ? "text-[hsl(120_80%_40%)] safe-glow"
                          : result.verdict === "suspicious"
                            ? "text-warning warning-glow"
                            : "text-destructive danger-glow"
                      }`}
                    >
                      {result.verdict === "safe" && (
                        <ShieldCheck className="w-8 h-8" />
                      )}
                      {result.verdict === "suspicious" && (
                        <AlertTriangle className="w-8 h-8" />
                      )}
                      {result.verdict === "phishing" && (
                        <Skull className="w-8 h-8" />
                      )}

                      {result.verdict === 'safe' ? "LOW RISK DETECTED" : result.verdict === 'suspicious' ? "SUSPICIOUS BAIT" : "PHISHING HOOK DETECTED"}

                    </h2>
                    <p className="text-sm font-mono text-muted-foreground break-all max-w-full overflow-hidden text-ellipsis px-4 bg-background/50 py-2 rounded border border-border">
                      {result.url}
                    </p>
                  </div>
                </div>

                {/* Detailed Analysis */}
                <div className="w-full md:w-2/3">
                  <h3 className="font-pirata text-3xl mb-6 text-foreground flex items-center gap-2">
                    <Info className="w-6 h-6 text-secondary" />
                    Sonar Analysis Log
                  </h3>

                  <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                    {result.checks.map((check, i) => (
                      <div
                        key={i}
                        className={`p-4 rounded-lg border-l-4 transition-colors ${
                          check.flag
                            ? "bg-destructive/10 border-destructive border-t border-r border-b border-t-destructive/20 border-r-destructive/20 border-b-destructive/20"
                            : "bg-background/50 border-border/50 border-t border-r border-b"
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className="mt-1 flex-shrink-0">
                            {check.flag ? (
                              <AlertTriangle className="w-5 h-5 text-destructive" />
                            ) : (
                              <ShieldCheck className="w-5 h-5 text-[hsl(120_80%_40%)] opacity-50" />
                            )}
                          </div>
                          <div>
                            <h4
                              className={`font-mono font-bold text-sm ${check.flag ? "text-destructive" : "text-muted-foreground"}`}
                            >
                              {check.name}
                            </h4>
                            <p className="text-sm text-foreground/70 mt-1">
                              {check.description}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* History */}
          <div className="md:col-span-1 wood-texture p-6 rounded-2xl h-fit">
            <h3 className="font-pirata text-2xl mb-4 flex items-center gap-2 text-foreground">
              <History className="w-5 h-5 text-secondary" />
              Captain's Log
            </h3>
            {history.length > 0 ? (
              <ul className="space-y-3">
                {history.map((h, i) => (
                  <li key={i}>
                    <button
                      onClick={() => setUrl(h)}
                      className="w-full text-left p-3 rounded bg-background/50 border border-border/50 hover:border-secondary/50 hover:bg-secondary/10 transition-colors font-mono text-sm truncate flex items-center gap-2 group"
                    >
                      <Clock className="w-4 h-4 text-muted-foreground group-hover:text-secondary flex-shrink-0" />
                      <span className="truncate">{h}</span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm font-mono text-muted-foreground text-center py-8 border-2 border-dashed border-border rounded-lg bg-background/20">
                No recent checks
              </p>
            )}
          </div>

          {/* How it works */}
          <div className="md:col-span-2 space-y-6">
            <h3 className="font-pirata text-3xl text-foreground text-center md:text-left">
              How to ?
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-card border border-border rounded-xl p-6 text-center hover-elevate shadow-md transition-transform hover:-translate-y-1">
                <div className="w-16 h-16 rounded-full bg-secondary/20 flex items-center justify-center mx-auto mb-4 border border-secondary/50 shadow-[inset_0_0_10px_rgba(20,200,200,0.3)]">
                  <Search className="w-8 h-8 text-secondary" />
                </div>
                <h4 className="font-mono font-bold mb-2">1. Cast Line</h4>
                <p className="text-sm text-muted-foreground">
                  Paste any suspicious URL into our sonar scanner above.
                </p>
              </div>
              <div className="bg-card border border-border rounded-xl p-6 text-center hover-elevate shadow-md transition-transform hover:-translate-y-1">
                <div className="w-16 h-16 rounded-full bg-warning/20 flex items-center justify-center mx-auto mb-4 border border-warning/50 shadow-[inset_0_0_10px_rgba(255,200,50,0.3)]">
                  <Waves className="w-8 h-8 text-warning" />
                </div>
                <h4 className="font-mono font-bold mb-2">2. Scan Waters</h4>
                <p className="text-sm text-muted-foreground">
                  We check for IP hosts, typosquatting, shorteners, and more.
                </p>
              </div>
              <div className="bg-card border border-border rounded-xl p-6 text-center hover-elevate shadow-md transition-transform hover:-translate-y-1">
                <div className="w-16 h-16 rounded-full bg-destructive/20 flex items-center justify-center mx-auto mb-4 border border-destructive/50 shadow-[inset_0_0_10px_rgba(255,50,50,0.3)]">
                  <LifeBuoy className="w-8 h-8 text-destructive" />
                </div>
                <h4 className="font-mono font-bold mb-2">3. Stay Safe</h4>
                <p className="text-sm text-muted-foreground">
                  Get a heuristic risk score. Low risk does not guarantee safety.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
      <footer className="py-6 text-center border-t border-border bg-sidebar-primary mt-auto relative z-20">
        <p className="font-mono text-sm text-muted-foreground flex items-center justify-center gap-2">
          <Anchor className="w-4 h-4 opacity-50" /> Built for the high seas of
          the internet
        </p>
      </footer>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <AppContent />
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
