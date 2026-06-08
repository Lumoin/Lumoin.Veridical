using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Pretty-printer for R1CS instances. Renders each constraint as a
/// human-readable line with variable names substituted where the
/// supplied <see cref="R1csVariableNames"/> registers them; otherwise
/// uses the standard <c>x_&lt;index&gt;</c> placeholder.
/// </summary>
/// <remarks>
/// <para>
/// The output is intended for debugging and diagnostic logs, not for
/// machine-readable interchange. Format is one line per constraint:
/// </para>
/// <code>
/// Curve: Bls12Curve381
/// c_0: (A_row) * (B_row) = (C_row)
/// </code>
/// <para>
/// Each <c>X_row</c> is a comma-separated list of <c>coefficient·variable</c>
/// pairs over the non-zero columns in that row.
/// </para>
/// </remarks>
public static class RawR1csInstanceFormatter
{
    /// <summary>Formats the entire instance as a multi-line string.</summary>
    public static string Format(RawR1csInstance instance, R1csVariableNames? variableNames = null)
    {
        ArgumentNullException.ThrowIfNull(instance);
        variableNames ??= R1csVariableNames.Empty;

        var builder = new StringBuilder();
        builder.Append("Curve: ").AppendLine(instance.Curve.ToString());
        for(int row = 0; row < instance.A.RowCount; row++)
        {
            builder.Append("c_").Append(row.ToString(CultureInfo.InvariantCulture)).Append(": (");
            AppendRow(builder, instance.A, row, variableNames);
            builder.Append(") * (");
            AppendRow(builder, instance.B, row, variableNames);
            builder.Append(") = (");
            AppendRow(builder, instance.C, row, variableNames);
            builder.AppendLine(")");
        }


        return builder.ToString();
    }


    private static void AppendRow(StringBuilder builder, R1csMatrix matrix, int targetRow, R1csVariableNames variableNames)
    {
        bool first = true;
        for(int i = 0; i < matrix.NonzeroCount; i++)
        {
            int row = BinaryPrimitives.ReadInt32BigEndian(matrix.GetRowIndicesBytes().Slice(i * sizeof(int), sizeof(int)));
            if(row != targetRow)
            {
                if(row > targetRow)
                {
                    return;
                }

                continue;
            }

            int column = BinaryPrimitives.ReadInt32BigEndian(matrix.GetColumnIndicesBytes().Slice(i * sizeof(int), sizeof(int)));
            string variableName = variableNames.GetOrPlaceholder(new R1csVariableIndex(column));
            string coefficientHex = Convert.ToHexStringLower(matrix.GetValueBytes(i));

            if(!first)
            {
                builder.Append(" + ");
            }

            builder.Append("0x").Append(coefficientHex).Append('·').Append(variableName);
            first = false;
        }

        if(first)
        {
            builder.Append('0');
        }
    }
}