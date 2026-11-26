// Link valid public identifiers only; never accept an advisory-supplied URL.
export default function CveLink({ cve }) {
	if (typeof cve !== "string" || !/^CVE-[0-9]{4}-[0-9]{4,}$/i.test(cve)) {
		return <span>{cve || "—"}</span>;
	}
	const id = cve.toUpperCase();
	return (
		<a
			className="text-primary-600 dark:text-primary-400 underline underline-offset-2 hover:text-primary-700 dark:hover:text-primary-300"
			href={`https://nvd.nist.gov/vuln/detail/${id}`}
			target="_blank"
			rel="noopener noreferrer"
			title="Open NIST National Vulnerability Database (new tab)"
		>
			{id}
		</a>
	);
}
