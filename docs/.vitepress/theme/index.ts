import DefaultTheme from "vitepress/theme";
import type { Theme } from "vitepress";
import { h } from "vue";
import "./custom.css";
import GitHubStarButton from "./GitHubStarButton.vue";

export default {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      "nav-bar-content-after": () => h(GitHubStarButton),
    });
  },
} satisfies Theme;
