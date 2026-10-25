"use client";
import styles from "./Odometer.module.css";

const digits = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

// each digit is a column that slides to its value; keyed from the right so columns persist
export default function Odometer({ value }: { value: number }) {
  const text = Math.max(0, Math.round(value || 0)).toLocaleString("en-US");
  const chars = [...text];
  return (
    <span className={styles.odo} aria-label={text}>
      {chars.map((ch, i) => {
        const key = chars.length - i;
        if (!/\d/.test(ch))
          return (
            <span key={`s${key}`} className={styles.sep} aria-hidden>
              {ch}
            </span>
          );
        return (
          <span key={`d${key}`} className={styles.col} aria-hidden>
            <span
              className={styles.strip}
              style={{ transform: `translateY(${-Number(ch) * 10}%)` }}
            >
              {digits.map((d) => (
                <span key={d}>{d}</span>
              ))}
            </span>
          </span>
        );
      })}
    </span>
  );
}
