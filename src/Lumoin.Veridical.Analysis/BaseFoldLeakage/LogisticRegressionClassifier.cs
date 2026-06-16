using System;

namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// A minimal binary logistic-regression classifier trained by batch gradient
/// descent with L2 regularisation. Deliberately simple — it is the "naive
/// classifier" of the leakage investigation, present to measure how much witness
/// structure a straightforward linear model can recover from proof bytes. A
/// near-chance result is an expected, honest outcome, not a failure: it bounds
/// what a simple attack recovers, not what a sophisticated one structurally could.
/// </summary>
internal static class LogisticRegressionClassifier
{
    /// <summary>
    /// Trains weights (with a leading bias term) on <paramref name="features"/>
    /// and 0/1 <paramref name="labels"/>. The returned vector has length
    /// <c>featureDimension + 1</c>; index 0 is the bias.
    /// </summary>
    internal static double[] Train(
        double[][] features,
        int[] labels,
        int iterations,
        double learningRate,
        double l2Regularisation)
    {
        int sampleCount = features.Length;
        int dimension = features[0].Length;
        double[] weights = new double[dimension + 1];
        double[] gradient = new double[dimension + 1];

        for(int iteration = 0; iteration < iterations; iteration++)
        {
            Array.Clear(gradient);
            for(int s = 0; s < sampleCount; s++)
            {
                double prediction = PredictProbability(weights, features[s]);
                double error = prediction - labels[s];
                gradient[0] += error;
                double[] sample = features[s];
                for(int j = 0; j < dimension; j++)
                {
                    gradient[j + 1] += error * sample[j];
                }
            }

            //Average the gradient, add the L2 term (not on the bias), and step.
            double scale = 1.0 / sampleCount;
            weights[0] -= learningRate * gradient[0] * scale;
            for(int j = 1; j <= dimension; j++)
            {
                double regularised = (gradient[j] * scale) + (l2Regularisation * weights[j]);
                weights[j] -= learningRate * regularised;
            }
        }

        return weights;
    }


    /// <summary>The fraction of <paramref name="features"/> whose predicted label matches <paramref name="labels"/>.</summary>
    internal static double Accuracy(double[] weights, double[][] features, int[] labels)
    {
        int correct = 0;
        for(int s = 0; s < features.Length; s++)
        {
            int predicted = PredictProbability(weights, features[s]) >= 0.5 ? 1 : 0;
            if(predicted == labels[s])
            {
                correct++;
            }
        }

        return (double)correct / features.Length;
    }


    private static double PredictProbability(double[] weights, double[] feature)
    {
        double sum = weights[0];
        for(int j = 0; j < feature.Length; j++)
        {
            sum += weights[j + 1] * feature[j];
        }

        return Sigmoid(sum);
    }


    private static double Sigmoid(double x)
    {
        //Numerically stable logistic function.
        if(x >= 0.0)
        {
            double z = Math.Exp(-x);
            return 1.0 / (1.0 + z);
        }

        double e = Math.Exp(x);
        return e / (1.0 + e);
    }
}
