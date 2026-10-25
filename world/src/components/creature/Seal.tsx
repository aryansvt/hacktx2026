import styles from "./creature.module.css";

// wax seal badge, used for threat and verdicts
export default function Seal({
  color,
  label,
  title,
  size = 64,
  className,
}: {
  color: string;
  label: string;
  title?: string;
  size?: number;
  className?: string;
}) {
  return (
    <span
      className={`${styles.seal} ${className ?? ""}`}
      title={title}
      style={
        {
          "--seal": color,
          width: size,
          height: size,
          fontSize: Math.max(10, size / 5.4),
        } as React.CSSProperties
      }
    >
      <span className={styles.sealInner}>{label}</span>
    </span>
  );
}
