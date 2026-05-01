"""Utilitários partilhados para o parsing de pacotes."""


def fmt_bytes(n):
    """Formata bytes em unidades legíveis (B, KB, MB, GB)."""
    if n < 1024:
        return f"{n}B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f}KB"
    elif n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f}MB"
    else:
        return f"{n / (1024 ** 3):.1f}GB"
