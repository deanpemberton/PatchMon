import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import CveLink from "./CveLink";

describe("CveLink", () => {
	it("links a CVE to its NVD description in a new tab", () => {
		render(<CveLink cve="cve-2026-111497" />);
		const link = screen.getByRole("link", { name: "CVE-2026-111497" });
		expect(link.getAttribute("href")).toBe(
			"https://nvd.nist.gov/vuln/detail/CVE-2026-111497",
		);
		expect(link.getAttribute("target")).toBe("_blank");
		expect(link.getAttribute("rel")).toBe("noopener noreferrer");
	});

	it("does not link a missing or malformed identifier", () => {
		const { rerender } = render(<CveLink cve={null} />);
		expect(screen.queryByRole("link")).toBeNull();
		rerender(<CveLink cve="CVE-2026-111497/other" />);
		expect(screen.queryByRole("link")).toBeNull();
	});
});
