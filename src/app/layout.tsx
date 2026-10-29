import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Two databases. One login. | Auth0 Lab",
  description: "A Next.js lab with automatic Auth0 database connection discovery.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
