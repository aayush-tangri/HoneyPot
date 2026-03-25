import { useState, useEffect } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { AttackTypeChart } from '@/components/charts/AttackTypeChart';
import { VolumeChart } from '@/components/charts/VolumeChart';
import { TrendingUp, Target } from 'lucide-react';
import { getAnalytics } from '@/lib/api';

const Analytics = () => {
  const [attackTypeData, setAttackTypeData] = useState<{ name: string; value: number }[]>([]);
  const [volumeData, setVolumeData] = useState<{ hour: string; attacks: number }[]>([]);
  const [topEndpoints, setTopEndpoints] = useState<{ endpoint: string; attacks: number }[]>([]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const data = await getAnalytics();
        if (cancelled) return;
        setAttackTypeData(data.attackTypeDistribution || []);
        setVolumeData(data.hourlyAttackVolume || []);
        setTopEndpoints(data.topEndpoints || []);
      } catch {
        if (!cancelled) {
          const { generateMockAttacks, getAttackTypeDistribution, getTopEndpoints, getHourlyAttackVolume } = await import('@/data/mockData');
          const mock = generateMockAttacks(100);
          setAttackTypeData(getAttackTypeDistribution(mock));
          setTopEndpoints(getTopEndpoints(mock));
          setVolumeData(getHourlyAttackVolume(mock));
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <DashboardLayout>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-foreground mb-1">Analytics</h1>
        <p className="text-sm text-muted-foreground">Threat insights and attack trends</p>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Attack Type Distribution */}
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-semibold text-foreground">Attack Type Distribution</h3>
          </div>
          <AttackTypeChart data={attackTypeData} />
        </div>

        {/* Top Attacked Endpoints */}
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="flex items-center gap-2 mb-4">
            <Target className="w-5 h-5 text-warning" />
            <h3 className="text-lg font-semibold text-foreground">Top Attacked Endpoints</h3>
          </div>
          <div className="space-y-3">
            {topEndpoints.map((item, index) => (
              <div key={item.endpoint} className="flex items-center gap-3">
                <span className="w-6 h-6 rounded bg-secondary flex items-center justify-center text-xs font-mono text-muted-foreground">
                  {index + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="font-mono text-sm text-foreground truncate">{item.endpoint}</p>
                  <div className="mt-1 h-1.5 bg-secondary rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-primary rounded-full transition-all duration-500"
                      style={{ width: `${topEndpoints[0]?.attacks ? (item.attacks / topEndpoints[0].attacks) * 100 : 0}%` }}
                    />
                  </div>
                </div>
                <span className="font-mono text-sm text-muted-foreground">{item.attacks}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Volume Over Time */}
      <div className="rounded-lg border border-border bg-card p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-semibold text-foreground">Attack Volume (24h)</h3>
          </div>
          <span className="text-xs text-muted-foreground">Hourly breakdown</span>
        </div>
        <VolumeChart data={volumeData} />
      </div>
    </DashboardLayout>
  );
};

export default Analytics;
