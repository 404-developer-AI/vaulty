using AngleSharp.Html.Parser;
using Vaulty.Infrastructure.Browse;
using Vaulty.Web.Browse;

namespace Vaulty.Integration.Tests.Browse;

public sealed class MailHtmlSanitizerTests
{
    /// <summary>Script injection and tracking patterns (a selection of well-known filter evasion cases).</summary>
    public static TheoryData<string> Corpus => new()
    {
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<scr<script>ipt>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
        "<img src=\"jav&#x09;ascript:alert(1)\">",
        "<svg onload=alert(1)><circle r=10 /></svg>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<a href=\"jav&#x09;ascript:alert(1)\">click</a>",
        "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">click</a>",
        "<a href=\"https://phish.example/login\" target=\"_top\">Your account</a>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
        "<body onload=alert(1)>text</body>",
        "<div style=\"background:url(javascript:alert(1))\">x</div>",
        "<div style=\"width: expression(alert(1))\">x</div>",
        "<div style=\"background-image:url(https://tracker.example/c.png)\">x</div>",
        "<form action=\"https://evil.example\"><input name=x><button>Send</button></form>",
        "<button formaction=javascript:alert(1)>x</button>",
        "<object data=\"data:text/html,<script>alert(1)</script>\"></object>",
        "<embed src=\"https://evil.example/x.swf\">",
        "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\">",
        "<base href=\"https://evil.example/\"><a href=\"x\">relative</a>",
        "<link rel=stylesheet href=\"https://evil.example/x.css\">",
        "<style>@import 'https://evil.example/x.css'; body { background: url(https://tracker.example/s.png) }</style>",
        "<img src=\"https://tracker.example/pixel.gif\" width=1 height=1>",
        "<img srcset=\"https://tracker.example/a.png 1x\">",
        "<img src=\"cid:image001.png@01DA\">",
        "<table background=\"https://tracker.example/b.png\"><tr><td>x</td></tr></table>",
        "<img src=\"data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+\">",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\"></noscript>",
        "<template><script>alert(1)</script></template>",
        "<details open ontoggle=alert(1)>x</details>",
        "<video><source onerror=alert(1)></video>",
        "<audio src=\"https://tracker.example/a.mp3\" autoplay></audio>",
        "<x onmouseover=alert(1)>hover</x>",
        "<input autofocus onfocus=alert(1)>",
        "<marquee onstart=alert(1)>x</marquee>",
        "<p data-x=\"1\" id=\"login\" name=\"x\">attributes</p>",
        "<div ping=\"https://tracker.example/p\">x</div>",
        "<!--[if gte mso 9]><script>alert(1)</script><![endif]-->",
        "<p>Plain <b>bold</b> <i>italic</i> <span style=\"color:#c00\">red</span></p>",
    };

    private static readonly HashSet<string> ForbiddenTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "script", "iframe", "frame", "object", "embed", "applet", "form", "input", "button", "select", "textarea", "svg", "math", "base", "link",
        "meta", "noscript", "template", "audio", "video", "source", "marquee",
    };

    [Theory]
    [MemberData(nameof(Corpus))]
    public void The_output_has_no_active_content_and_loads_nothing_from_elsewhere(string html)
    {
        var output = MailHtmlSanitizer.Sanitize(html);
        var document = new HtmlParser().ParseDocument(output);

        // Our own document: one style element in the head, nothing else in it.
        Assert.Single(document.Head!.QuerySelectorAll("style"));
        foreach (var element in document.Body!.QuerySelectorAll("*"))
        {
            Assert.DoesNotContain(element.LocalName, ForbiddenTags);
            Assert.NotEqual("style", element.LocalName);
            foreach (var attribute in element.Attributes)
            {
                Assert.False(attribute.Name.StartsWith("on", StringComparison.OrdinalIgnoreCase), $"event handler {attribute.Name} in {output}");
                Assert.NotEqual("href", attribute.Name);
                Assert.NotEqual("srcset", attribute.Name);
                Assert.NotEqual("background", attribute.Name);
                Assert.NotEqual("ping", attribute.Name);
                Assert.NotEqual("action", attribute.Name);
                Assert.NotEqual("formaction", attribute.Name);
                Assert.NotEqual("srcdoc", attribute.Name);
                Assert.False(attribute.Name.StartsWith("data-", StringComparison.Ordinal), $"data attribute in {output}");
                Assert.DoesNotContain("javascript:", attribute.Value, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("vbscript:", attribute.Value, StringComparison.OrdinalIgnoreCase);
                if (attribute.Name == "src")
                {
                    Assert.Matches("^data:image/(png|jpeg|gif|webp|bmp);", attribute.Value);
                }
                if (attribute.Name == "style")
                {
                    Assert.DoesNotContain("url(", attribute.Value, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("expression", attribute.Value, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    [Fact]
    public void Readable_content_survives()
    {
        var output = MailHtmlSanitizer.Sanitize(
            "<p>Hello <b>Anna</b>,</p><p>See <a href=\"https://contoso.example/report\">the report</a>.</p>" +
            "<img src=\"data:image/png;base64,iVBORw0KGgo=\" alt=\"logo\"><img src=\"https://tracker.example/p.gif\">" +
            "<table><tr><td style=\"color:#c00\">Total</td></tr></table>");
        var document = new HtmlParser().ParseDocument(output);
        Assert.Equal("Anna", document.QuerySelector("b")?.TextContent);
        var link = document.QuerySelector("a")!;
        Assert.Equal("the report", link.TextContent);
        Assert.Equal("https://contoso.example/report", link.GetAttribute("title"));
        var images = document.QuerySelectorAll("img");
        Assert.Equal("data:image/png;base64,iVBORw0KGgo=", images[0].GetAttribute("src"));
        Assert.Null(images[1].GetAttribute("src"));
        Assert.Equal(MailHtmlSanitizer.BlockedImageText, images[1].GetAttribute("alt"));
        Assert.Contains("color", document.QuerySelector("td")!.GetAttribute("style"), StringComparison.Ordinal);
    }

    [Fact]
    public void Preview_responses_forbid_scripts_and_loading_from_elsewhere()
    {
        foreach (var policy in new[] { PreviewEndpoints.HtmlPolicy, PreviewEndpoints.FilePolicy })
        {
            Assert.Contains("default-src 'none'", policy, StringComparison.Ordinal);
            Assert.Contains("sandbox", policy, StringComparison.Ordinal);
            Assert.DoesNotContain("script-src", policy, StringComparison.Ordinal);
            Assert.Contains("frame-ancestors 'self'", policy, StringComparison.Ordinal);
        }
        Assert.Contains("img-src data:", PreviewEndpoints.HtmlPolicy, StringComparison.Ordinal);
        Assert.Contains("default-src 'none'", PreviewEndpoints.PdfPolicy, StringComparison.Ordinal);
        Assert.Equal("Report_2026_.pdf", PreviewEndpoints.SafeFileName("Report\"2026\r.pdf"));

        // The browser page embeds HTML and text previews in an iframe without any sandbox permissions.
        var page = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "Vaulty.Web", "Components", "Pages", "Objects",
            "SnapshotBrowse.razor"));
        Assert.Contains("<iframe class=\"vy-preview\" sandbox=\"\"", page, StringComparison.Ordinal);
    }
}
