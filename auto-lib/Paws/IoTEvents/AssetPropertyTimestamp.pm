# Generated by default/object.tt
package Paws::IoTEvents::AssetPropertyTimestamp;
  use Moose;
  has OffsetInNanos => (is => 'ro', isa => 'Str', request_name => 'offsetInNanos', traits => ['NameInRequest']);
  has TimeInSeconds => (is => 'ro', isa => 'Str', request_name => 'timeInSeconds', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoTEvents::AssetPropertyTimestamp

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoTEvents::AssetPropertyTimestamp object:

  $service_obj->Method(Att1 => { OffsetInNanos => $value, ..., TimeInSeconds => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoTEvents::AssetPropertyTimestamp object:

  $result = $service_obj->Method(...);
  $result->Att1->OffsetInNanos

=head1 DESCRIPTION

A structure that contains timestamp information. For more information,
see TimeInNanos
(https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_TimeInNanos.html)
in the I<AWS IoT SiteWise API Reference>.

You must use expressions for all parameters in
C<AssetPropertyTimestamp>. The expressions accept literals, operators,
functions, references, and substitution templates.

B<Examples>

=over

=item *

For literal values, the expressions must contain single quotes. For
example, the value for the C<timeInSeconds> parameter can be
C<'1586400675'>.

=item *

For references, you must specify either variables or input values. For
example, the value for the C<offsetInNanos> parameter can be
C<$variable.time>.

=item *

For a substitution template, you must use C<${}>, and the template must
be in single quotes. A substitution template can also contain a
combination of literals, operators, functions, references, and
substitution templates.

In the following example, the value for the C<timeInSeconds> parameter
uses a substitution template.

C<'${$input.TemperatureInput.sensorData.timestamp / 1000}'>

=back

For more information, see Expressions
(https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-expressions.html)
in the I<AWS IoT Events Developer Guide>.

=head1 ATTRIBUTES


=head2 OffsetInNanos => Str

The nanosecond offset converted from C<timeInSeconds>. The valid range
is between 0-999999999.


=head2 B<REQUIRED> TimeInSeconds => Str

The timestamp, in seconds, in the Unix epoch format. The valid range is
between 1-31556889864403199.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoTEvents>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

