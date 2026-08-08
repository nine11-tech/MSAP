export function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <svg
        className="brand-mark-icon"
        viewBox="0 0 24 24"
        role="presentation"
        focusable="false"
      >
        <path d="m7.3 6.7-1.4-2.3M16.7 6.7l1.4-2.3" />
        <path d="M5.2 10.2c.5-3.2 3.1-5 6.8-5s6.3 1.8 6.8 5H5.2Z" />
        <path d="M5 11.6h14v6.2a1.7 1.7 0 0 1-1.7 1.7H6.7A1.7 1.7 0 0 1 5 17.8v-6.2Z" />
        <circle cx="9" cy="8.4" r=".75" className="brand-mark-eye" />
        <circle cx="15" cy="8.4" r=".75" className="brand-mark-eye" />
      </svg>
    </span>
  );
}
