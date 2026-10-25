import styles from "./Footer.module.css";

export default function Footer() {
  return (
    <footer className={styles.footer}>
      This is a research honeypot built for HackTX 2026. Connection data is
      anonymized and deleted after the event.
    </footer>
  );
}
