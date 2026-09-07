export const PayloadViewer = ({ text = "", testId }) => {
  const html = (text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (m) => `<span class="ioc-ip">${m}</span>`)
    .replace(/\b[a-fA-F0-9]{32,64}\b/g, (m) => `<span class="ioc-hash">${m}</span>`)
    .replace(/\b(?:[a-zA-Z0-9-]{2,63}\.)+[a-zA-Z]{2,10}\b/g, (m) => {
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(m)) return m;
      return `<span class="ioc-domain">${m}</span>`;
    });
  return (
    <div
      className="payload-viewer"
      data-testid={testId}
      dangerouslySetInnerHTML={{ __html: html || "<span class='text-neutral-600'>(no payload)</span>" }}
    />
  );
};
