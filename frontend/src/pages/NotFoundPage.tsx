import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <section>
      <h1 className="text-2xl font-semibold tracking-tight">Page not found</h1>
      <Link to="/" className="mt-3 inline-block text-sm text-blue-700 underline">
        Back to status
      </Link>
    </section>
  );
}
