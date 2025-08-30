
export default function Footer() {
  return (
    <footer className="border-t">
      <div className="container mx-auto p-4 text-sm text-gray-500">
        © {new Date().getFullYear()} RS-SHOP. All rights reserved.
      </div>
    </footer>
  );
}
